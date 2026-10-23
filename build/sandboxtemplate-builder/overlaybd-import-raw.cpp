/*
 * overlaybd-import-raw — import a raw disk/memory image into an OverlayBD
 * LSMT commit layer.
 *
 * The source is scanned in fixed windows; fully zero windows are omitted
 * and leading/trailing zero blocks are trimmed, keeping at most one mapping
 * per window so ext4 metadata does not produce millions of index entries.
 * Data is written in ascending offset order, flushed periodically, sealed
 * in place (append-only compaction equivalent), and the complete logical
 * address space is verified byte-for-byte against the source before the
 * layer is published.
 *
 * Linked against the containerd/overlaybd library (photon + lsmt).
 *
 * Usage: overlaybd-import-raw SOURCE_RAW DATA_FILE INDEX_FILE COMMIT_FILE
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <vector>

#include <photon/common/alog.h>
#include <photon/fs/localfs.h>
#include <photon/photon.h>

#include "../overlaybd/lsmt/file.h"

using photon::fs::IFile;

namespace {

constexpr size_t kSectorSize = 512;
constexpr size_t kZeroBlockSize = 4096;
constexpr size_t kBufferSize = 4 * 1024 * 1024;

[[noreturn]] void fail(const char *message, const char *path = nullptr) {
    fprintf(stderr, "overlaybd-import-raw: %s '%s': %s\n", message,
            path ? path : "", strerror(errno));
    exit(EXIT_FAILURE);
}

IFile *open_photon_file(const char *path, int flags, mode_t mode = 0) {
    IFile *file = photon::fs::open_localfile_adaptor(path, flags, mode, 0);
    if (file == nullptr) {
        fail("failed to open", path);
    }
    return file;
}

bool all_zero(const unsigned char *buffer, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (buffer[i] != 0) {
            return false;
        }
    }
    return true;
}

void write_exact(IFile *layer, const void *buffer, size_t count, off_t offset) {
    ssize_t written = layer->pwrite(buffer, count, offset);
    if (written != static_cast<ssize_t>(count)) {
        if (written >= 0) {
            errno = EIO;
        }
        fail("failed to write OverlayBD layer");
    }
}

struct ImportStats {
    uint64_t logical_bytes = 0;
    uint64_t stored_bytes = 0;
    uint64_t mappings = 0;
};

ImportStats import_raw(int source_fd, uint64_t source_size, LSMT::IFileRW *layer,
                       IFile *data_file) {
    std::vector<unsigned char> buffer(kBufferSize);
    ImportStats stats;
    stats.logical_bytes = source_size;
    uint64_t cache_drop_offset = 0;

    for (uint64_t offset = 0; offset < source_size;) {
        size_t count = static_cast<size_t>(
            std::min<uint64_t>(buffer.size(), source_size - offset));
        size_t done = 0;
        while (done < count) {
            ssize_t nread = pread(source_fd, buffer.data() + done, count - done,
                                  static_cast<off_t>(offset + done));
            if (nread < 0) {
                if (errno == EINTR) {
                    continue;
                }
                fail("failed to read source raw image");
            }
            if (nread == 0) {
                errno = EIO;
                fail("unexpected end of source raw image");
            }
            done += static_cast<size_t>(nread);
        }

        // At most one mapping per 4 MiB window: skip fully zero windows,
        // omit leading/trailing zero blocks, store the rest verbatim.
        size_t first_nonzero = count;
        size_t last_nonzero = 0;
        for (size_t cursor = 0; cursor < count; cursor += kZeroBlockSize) {
            size_t block_size = std::min(kZeroBlockSize, count - cursor);
            if (!all_zero(buffer.data() + cursor, block_size)) {
                first_nonzero = std::min(first_nonzero, cursor);
                last_nonzero = cursor + block_size;
            }
        }
        if (first_nonzero != count) {
            size_t stored_size = last_nonzero - first_nonzero;
            write_exact(layer, buffer.data() + first_nonzero, stored_size,
                        static_cast<off_t>(offset + first_nonzero));
            stats.stored_bytes += stored_size;
            ++stats.mappings;
        }
        offset += count;

        // Periodic flush plus dropping scanned source pages from the cache
        // keeps peak memory bounded for multi-GiB images. offset == 0 must
        // not flush: fadvise with len 0 means "to EOF" and would drop the
        // whole source file's page cache on the first iteration.
        constexpr uint64_t kFlushInterval = 256ULL * 1024 * 1024;
        if ((offset > 0 && offset % kFlushInterval == 0) || offset == source_size) {
            if (data_file->fsync() != 0) {
                fail("failed to sync writable OverlayBD layer");
            }
            if (posix_fadvise(source_fd, static_cast<off_t>(cache_drop_offset),
                              static_cast<off_t>(offset - cache_drop_offset),
                              POSIX_FADV_DONTNEED) != 0) {
                fprintf(stderr, "warning: failed to drop source page cache: %s\n",
                        strerror(errno));
            }
            cache_drop_offset = offset;
        }
    }
    return stats;
}

void verify_commit(int source_fd, uint64_t source_size, const char *commit_path) {
    std::unique_ptr<IFile> commit_file(open_photon_file(commit_path, O_RDONLY));
    std::unique_ptr<LSMT::IFileRO> layer(LSMT::open_file_ro(commit_file.release(), true));
    if (!layer) {
        errno = EINVAL;
        fail("failed to reopen committed OverlayBD layer", commit_path);
    }
    struct stat st {};
    if (layer->fstat(&st) != 0 || static_cast<uint64_t>(st.st_size) != source_size) {
        errno = EINVAL;
        fail("OverlayBD virtual size does not match source");
    }
    std::vector<unsigned char> source(kBufferSize);
    std::vector<unsigned char> restored(kBufferSize);
    for (uint64_t offset = 0; offset < source_size;) {
        size_t count = static_cast<size_t>(
            std::min<uint64_t>(source.size(), source_size - offset));
        size_t done = 0;
        while (done < count) {
            ssize_t nread = pread(source_fd, source.data() + done, count - done,
                                  static_cast<off_t>(offset + done));
            if (nread < 0) {
                if (errno == EINTR) {
                    continue;
                }
                fail("failed to read source for verification");
            }
            done += static_cast<size_t>(nread);
        }
        ssize_t nread = layer->pread(restored.data(), count, static_cast<off_t>(offset));
        if (nread != static_cast<ssize_t>(count)) {
            if (nread >= 0) {
                errno = EIO;
            }
            fail("failed to read committed OverlayBD layer");
        }
        if (memcmp(source.data(), restored.data(), count) != 0) {
            fprintf(stderr, "overlaybd-import-raw: verification mismatch at offset=%" PRIu64 "\n",
                    offset);
            exit(EXIT_FAILURE);
        }
        offset += count;
    }
}

}  // namespace

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr,
                "usage: overlaybd-import-raw SOURCE_RAW DATA_FILE INDEX_FILE COMMIT_FILE\n");
        return EXIT_FAILURE;
    }
    const char *source_path = argv[1];
    const char *data_path = argv[2];
    const char *index_path = argv[3];
    const char *commit_path = argv[4];

    int source_fd = open(source_path, O_RDONLY | O_CLOEXEC);
    if (source_fd < 0) {
        fail("failed to open", source_path);
    }
    struct stat source_stat {};
    if (fstat(source_fd, &source_stat) != 0) {
        fail("failed to stat", source_path);
    }
    if (!S_ISREG(source_stat.st_mode) || source_stat.st_size <= 0 ||
        source_stat.st_size % kSectorSize != 0) {
        fprintf(stderr, "source must be a non-empty, 512-byte-aligned regular file\n");
        return EXIT_FAILURE;
    }

    set_log_output_level(1);
    if (photon::init(photon::INIT_EVENT_DEFAULT, photon::INIT_IO_DEFAULT) != 0) {
        fail("failed to initialize Photon");
    }

    const int create_flags = O_RDWR | O_CREAT | O_EXCL;
    const mode_t create_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    std::unique_ptr<IFile> data(open_photon_file(data_path, create_flags, create_mode));
    std::unique_ptr<IFile> index(open_photon_file(index_path, create_flags, create_mode));

    LSMT::LayerInfo layer_info(data.get(), index.get());
    layer_info.virtual_size = static_cast<uint64_t>(source_stat.st_size);
    // LayerInfo defaults to append mode in both supported OverlayBD APIs.
    std::unique_ptr<LSMT::IFileRW> layer(LSMT::create_file_rw(layer_info, false));
    if (!layer) {
        errno = EIO;
        fail("failed to create writable OverlayBD layer");
    }

    ImportStats stats = import_raw(source_fd,
                                   static_cast<uint64_t>(source_stat.st_size),
                                   layer.get(), data.get());

    // The importer writes each virtual range only once and in ascending
    // order, so sealing the append-only layer is equivalent to compacting
    // it, while avoiding a second full-size copy and its page-cache
    // pressure.
    if (layer->close_seal() != 0) {
        fail("failed to seal OverlayBD layer", data_path);
    }
    if (data->fsync() != 0) {
        fail("failed to sync sealed OverlayBD layer", data_path);
    }

    layer.reset();
    data.reset();
    index.reset();

    if (access(commit_path, F_OK) == 0) {
        errno = EEXIST;
        fail("refusing to overwrite", commit_path);
    }
    if (errno != ENOENT) {
        fail("failed to check output", commit_path);
    }
    if (rename(data_path, commit_path) != 0) {
        fail("failed to publish sealed OverlayBD layer", commit_path);
    }

    verify_commit(source_fd, static_cast<uint64_t>(source_stat.st_size), commit_path);
    close(source_fd);
    photon::fini();

    printf("OVERLAYBD_IMPORT_SUCCEEDED logical_bytes=%" PRIu64
           " stored_bytes=%" PRIu64 " mappings=%" PRIu64 "\n",
           stats.logical_bytes, stats.stored_bytes, stats.mappings);
    return EXIT_SUCCESS;
}

package agent

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const singlePutLimit int64 = 5 << 30

type completedPart struct {
	Number int    `xml:"PartNumber"`
	ETag   string `xml:"ETag"`
}

// putMultipart streams seekable artifacts one part at a time. Reopening and
// seeking per attempt keeps retry memory bounded, even for multi-GiB bases.
func (c *s3Client) putMultipart(ctx context.Context, target string, size, partSize int64, open func() (io.ReadCloser, error)) (resultErr error) {
	payload, _, err := c.multipartRequest(ctx, http.MethodPost, target, [][2]string{{"uploads", ""}}, nil, 0)
	if err != nil {
		return err
	}
	var started struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(payload, &started); err != nil {
		return fmt.Errorf("decode multipart upload: %w", err)
	}
	if started.UploadID == "" {
		return fmt.Errorf("multipart upload has no upload ID")
	}
	query := [][2]string{{"uploadId", started.UploadID}}
	defer func() {
		if resultErr == nil {
			return
		}
		// Cleanup must still run after cancellation of the publishing worker.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_, _, err := c.multipartRequest(cleanup, http.MethodDelete, target, query, nil, 0)
		var status *httpError
		if err != nil && !(errors.As(err, &status) && status.StatusCode == http.StatusNotFound) {
			resultErr = errors.Join(resultErr, fmt.Errorf("abort multipart upload: %w", err))
		}
	}()
	var complete struct {
		XMLName xml.Name        `xml:"CompleteMultipartUpload"`
		XMLNS   string          `xml:"xmlns,attr"`
		Parts   []completedPart `xml:"Part"`
	}
	complete.XMLNS = "http://s3.amazonaws.com/doc/2006-03-01/"
	for offset, number := int64(0), 1; offset < size; number++ {
		length := min(partSize, size-offset)
		etag, err := c.uploadPart(ctx, target, started.UploadID, number, offset, length, open)
		if err != nil {
			return fmt.Errorf("upload part %d: %w", number, err)
		}
		complete.Parts = append(complete.Parts, completedPart{Number: number, ETag: etag})
		offset += length
	}
	body, err := xml.Marshal(complete)
	if err != nil {
		return err
	}
	payload, _, err = c.multipartRequest(ctx, http.MethodPost, target, query, bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return err
	}
	var finished struct {
		XMLName xml.Name
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	if err := xml.Unmarshal(payload, &finished); err != nil {
		return fmt.Errorf("decode completed multipart upload: %w", err)
	}
	// S3 can send HTTP 200 before an eventual XML Error. Never publish a
	// manifest referring to such an incomplete artifact.
	if finished.XMLName.Local != "CompleteMultipartUploadResult" {
		return fmt.Errorf("complete multipart upload: %s: %s", finished.Code, finished.Message)
	}
	return nil
}

func (c *s3Client) uploadPart(ctx context.Context, target, uploadID string, number int, offset, size int64, open func() (io.ReadCloser, error)) (string, error) {
	query := [][2]string{{"partNumber", strconv.Itoa(number)}, {"uploadId", uploadID}}
	var lastErr error
	for attempt := 0; attempt <= s3RetryAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(c.retryDelay * time.Duration(1<<(attempt-1))):
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		body, err := open()
		if err != nil {
			return "", err
		}
		seeker, ok := body.(io.Seeker)
		if !ok {
			_ = body.Close()
			return "", fmt.Errorf("multipart artifact must be seekable")
		}
		if _, err := seeker.Seek(offset, io.SeekStart); err != nil {
			_ = body.Close()
			return "", err
		}
		_, etag, err := c.multipartRequest(ctx, http.MethodPut, target, query, io.LimitReader(body, size), size)
		_ = body.Close()
		if err == nil {
			if etag == "" {
				return "", fmt.Errorf("uploaded part has no ETag")
			}
			return etag, nil
		}
		var status *httpError
		if errors.As(err, &status) && status.StatusCode < http.StatusInternalServerError {
			return "", err
		}
		lastErr = err
	}
	return "", lastErr
}

func (c *s3Client) multipartRequest(ctx context.Context, method, target string, query [][2]string, body io.Reader, size int64) ([]byte, string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, "", err
	}
	u.RawQuery = canonicalQueryString(query)
	request, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, "", err
	}
	request.ContentLength = size
	request.Header.Set("Content-Type", "application/xml")
	c.signWrite(request)
	response, err := c.putHTTP.Do(request)
	if err != nil {
		return nil, "", err
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return nil, "", err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, "", &httpError{StatusCode: response.StatusCode, Body: string(payload)}
	}
	return payload, response.Header.Get("ETag"), nil
}

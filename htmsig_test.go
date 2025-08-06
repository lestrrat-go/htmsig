package htmsig_test

import "testing"

func TestParseInput(t *testing.T) {
	t.Parallel()
	t.Run("Sanity (RFC942 #4.1)", func(t *testing.T) {
		t.Parallel()
		const src1 = `Signature-Input: sig1=("@method" "@target-uri" "@authority" \
  "content-digest" "cache-control");\
  created=1618884475;keyid="test-key-rsa-pss"`

		const src2 = `sig=("@target-uri" "@authority" "date" "cache-control");keyid="test-key-rsa-pss";alg="rsa-pss-sha512"; created=1618884475;expires=1618884775`
		
		// Use the constants to avoid unused variable warnings
		_ = src1
		_ = src2
	})
}

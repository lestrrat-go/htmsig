package input_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/htmsig/input"
	"github.com/stretchr/testify/require"
)

func TestParseSignatureInput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *input.Value
	}{
		{
			name: "Single signature with basic parameters",
			// Example from RFC 9421: sig1=("@method" "@target-uri" "@authority" "content-digest" "content-length" "content-type");created=1618884473;keyid="test-key-rsa-pss"
			input: `sig1=("@method" "@target-uri" "@authority" "content-digest" "content-length" "content-type");created=1618884473;keyid="test-key-rsa-pss"`,
			expected: input.NewValueBuilder().
				AddDefinition(
					input.NewDefinitionBuilder().
						Label("sig1").
						Components(input.MethodComponent, input.TargetURIComponent, input.AuthorityComponent, "content-digest", "content-length", "content-type").
						KeyID("test-key-rsa-pss").
						Algorithm("rsa-pss-sha256").
						Created(1618884473).
						MustBuild(),
				).
				MustBuild(),
		},
		{
			name: "Multiple signatures",
			// sig1=(...);created=1618884473;keyid="test-key-rsa-pss", sig2=(...);created=1618884474;keyid="test-key-ed25519"
			input: `sig1=("@method" "@target-uri");created=1618884473;keyid="test-key-rsa-pss", sig2=("content-digest");created=1618884474;keyid="test-key-ed25519"`,
			expected: input.NewValueBuilder().
				AddDefinition(
					input.NewDefinitionBuilder().
						Label("sig1").
						Components(input.MethodComponent, input.TargetURIComponent).
						KeyID("test-key-rsa-pss").
						Algorithm("rsa-pss-sha256").
						Created(1618884473).
						MustBuild(),
				).
				AddDefinition(
					input.NewDefinitionBuilder().
						Label("sig2").
						Components("content-digest").
						KeyID("test-key-ed25519").
						Algorithm("ed25519").
						Created(1618884474).
						MustBuild(),
				).
				MustBuild(),
		},
		{
			name:  "Signature with all optional parameters",
			input: `sig1=("@method");created=1618884473;expires=1618888073;nonce="b3c2a1";keyid="test-key";tag="example"`,
			expected: input.NewValueBuilder().
				AddDefinition(
					input.NewDefinitionBuilder().
						Label("sig1").
						Components(input.MethodComponent).
						KeyID("test-key").
						Algorithm("rsa-pss-sha256").
						Created(1618884473).
						Expires(1618888073).
						Nonce("b3c2a1").
						Tag("example").
						MustBuild(),
				).
				MustBuild(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := input.Parse([]byte(tt.input))
			require.NoError(t, err, "Parse should succeed for valid input")
			require.NotNil(t, result, "Result should not be nil")

			// Check number of definitions
			require.Equal(t, tt.expected.Len(), result.Len(), "Number of definitions should match")

			// Check each definition
			for i, expectedDef := range tt.expected.Definitions() {
				actualDef := result.Definitions()[i]
				require.Equal(t, expectedDef.Label(), actualDef.Label(), "Label should match")
				require.Equal(t, expectedDef.Components(), actualDef.Components(), "Components should match")
				require.Equal(t, expectedDef.KeyID(), actualDef.KeyID(), "KeyID should match")

				// Check optional parameters
				expectedCreated, expectedHasCreated := expectedDef.Created()
				actualCreated, actualHasCreated := actualDef.Created()
				require.Equal(t, expectedHasCreated, actualHasCreated, "Created presence should match")
				if expectedHasCreated {
					require.Equal(t, expectedCreated, actualCreated, "Created timestamp should match")
				}

				expectedExpires, expectedHasExpires := expectedDef.Expires()
				actualExpires, actualHasExpires := actualDef.Expires()
				require.Equal(t, expectedHasExpires, actualHasExpires, "Expires presence should match")
				if expectedHasExpires {
					require.Equal(t, expectedExpires, actualExpires, "Expires timestamp should match")
				}

				expectedNonce, expectedHasNonce := expectedDef.Nonce()
				actualNonce, actualHasNonce := actualDef.Nonce()
				require.Equal(t, expectedHasNonce, actualHasNonce, "Nonce presence should match")
				if expectedHasNonce {
					require.Equal(t, expectedNonce, actualNonce, "Nonce should match")
				}

				expectedTag, expectedHasTag := expectedDef.Tag()
				actualTag, actualHasTag := actualDef.Tag()
				require.Equal(t, expectedHasTag, actualHasTag, "Tag presence should match")
				if expectedHasTag {
					require.Equal(t, expectedTag, actualTag, "Tag should match")
				}
			}
		})
	}
}

func TestDefinitionTimeConvenience(t *testing.T) {
	now := time.Now()
	def := input.NewDefinitionBuilder().
		Label("test").
		Components(input.MethodComponent).
		KeyID("key1").
		Algorithm("rsa-pss-sha256").
		CreatedTime(now).
		MustBuild()

	createdTime, ok := def.CreatedTime()
	require.True(t, ok, "Should have created time")
	require.Equal(t, now.Unix(), createdTime.Unix(), "Created time should match")

	// Test timestamp methods
	timestamp, ok := def.Created()
	require.True(t, ok, "Should have created timestamp")
	require.Equal(t, now.Unix(), timestamp, "Timestamp should match")
}

func TestValueManagement(t *testing.T) {
	def1 := input.NewDefinitionBuilder().
		Label("sig1").
		Components(input.MethodComponent).
		KeyID("key1").
		Algorithm("rsa-pss-sha256").
		MustBuild()

	def2 := input.NewDefinitionBuilder().
		Label("sig2").
		Components("content-digest").
		KeyID("key2").
		Algorithm("ed25519").
		MustBuild()

	v := input.NewValueBuilder().
		AddDefinition(def1).
		AddDefinition(def2).
		MustBuild()

	require.Equal(t, 2, v.Len(), "Should have 2 definitions")

	// Test GetDefinition
	found, ok := v.GetDefinition("sig1")
	require.True(t, ok, "Should find sig1")
	require.Equal(t, "sig1", found.Label(), "Should return correct definition")

	_, ok = v.GetDefinition("nonexistent")
	require.False(t, ok, "Should not find nonexistent definition")
}

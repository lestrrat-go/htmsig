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
		{
			name:  "Signature with arbitrary parameters",
			input: `sig1=("@method" "@authority");created=1618884473;keyid="test-key";alg="rsa-pss-sha256";priority=5;region="us-east-1";debug=?1;custom-header="custom-value"`,
			expected: input.NewValueBuilder().
				AddDefinition(
					input.NewDefinitionBuilder().
						Label("sig1").
						Components(input.MethodComponent, input.AuthorityComponent).
						KeyID("test-key").
						Algorithm("rsa-pss-sha256").
						Created(1618884473).
						Parameter("priority", int64(5)).
						Parameter("region", "us-east-1").
						Parameter("debug", true).
						Parameter("custom-header", "custom-value").
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

				// Check arbitrary parameters
				expectedParams := expectedDef.Parameters()
				actualParams := actualDef.Parameters()

				// Compare parameter counts (ignoring standard parameters like created, expires, etc.)
				require.Equal(t, len(expectedParams.Values), len(actualParams.Values), "Number of arbitrary parameters should match")

				// Check each arbitrary parameter
				for key, expectedValue := range expectedParams.Values {
					actualValue, exists := actualParams.Values[key]
					require.True(t, exists, "Parameter %s should exist", key)
					require.Equal(t, expectedValue, actualValue, "Parameter %s value should match", key)
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

func TestMarshalSFVRoundtrip(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Single signature with basic parameters",
			input: `sig1=("@method" "@target-uri" "@authority" "content-digest");created=1618884473;keyid="test-key-rsa-pss";alg="rsa-pss-sha256"`,
		},
		{
			name:  "Multiple signatures",
			input: `sig1=("@method" "@target-uri");created=1618884473;keyid="test-key-rsa-pss";alg="rsa-pss-sha256", sig2=("content-digest");created=1618884474;keyid="test-key-ed25519";alg="ed25519"`,
		},
		{
			name:  "Signature with all optional parameters",
			input: `sig1=("@method");created=1618884473;expires=1618888073;nonce="b3c2a1";keyid="test-key";alg="rsa-pss-sha256";tag="example"`,
		},
		{
			name:  "Signature with arbitrary parameters",
			input: `sig1=("@method" "@authority");created=1618884473;keyid="test-key";alg="rsa-pss-sha256";priority=5;region="us-east-1";debug=?1;custom-header="custom-value"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the input
			value, err := input.Parse([]byte(tt.input))
			require.NoError(t, err, "Parse should succeed")

			// Marshal it back
			marshaled, err := value.MarshalSFV()
			require.NoError(t, err, "MarshalSFV should succeed")

			// Parse the marshaled result
			reparsed, err := input.Parse(marshaled)
			require.NoError(t, err, "Reparsing marshaled result should succeed")

			// Verify they're equivalent
			require.Equal(t, value.Len(), reparsed.Len(), "Number of definitions should match")

			for i, originalDef := range value.Definitions() {
				reparsedDef := reparsed.Definitions()[i]

				require.Equal(t, originalDef.Label(), reparsedDef.Label(), "Label should match")
				require.Equal(t, originalDef.Components(), reparsedDef.Components(), "Components should match")
				require.Equal(t, originalDef.KeyID(), reparsedDef.KeyID(), "KeyID should match")
				require.Equal(t, originalDef.Algorithm(), reparsedDef.Algorithm(), "Algorithm should match")

				// Check optional parameters
				originalCreated, originalHasCreated := originalDef.Created()
				reparsedCreated, reparsedHasCreated := reparsedDef.Created()
				require.Equal(t, originalHasCreated, reparsedHasCreated, "Created presence should match")
				if originalHasCreated {
					require.Equal(t, originalCreated, reparsedCreated, "Created timestamp should match")
				}

				originalExpires, originalHasExpires := originalDef.Expires()
				reparsedExpires, reparsedHasExpires := reparsedDef.Expires()
				require.Equal(t, originalHasExpires, reparsedHasExpires, "Expires presence should match")
				if originalHasExpires {
					require.Equal(t, originalExpires, reparsedExpires, "Expires timestamp should match")
				}

				originalNonce, originalHasNonce := originalDef.Nonce()
				reparsedNonce, reparsedHasNonce := reparsedDef.Nonce()
				require.Equal(t, originalHasNonce, reparsedHasNonce, "Nonce presence should match")
				if originalHasNonce {
					require.Equal(t, originalNonce, reparsedNonce, "Nonce should match")
				}

				originalTag, originalHasTag := originalDef.Tag()
				reparsedTag, reparsedHasTag := reparsedDef.Tag()
				require.Equal(t, originalHasTag, reparsedHasTag, "Tag presence should match")
				if originalHasTag {
					require.Equal(t, originalTag, reparsedTag, "Tag should match")
				}
			}
		})
	}
}

func TestDefinitionMarshalSFV(t *testing.T) {
	def := input.NewDefinitionBuilder().
		Label("sig1").
		Components("@method", "@target-uri", "content-digest").
		KeyID("test-key-rsa-pss").
		Algorithm("rsa-pss-sha256").
		Created(1618884473).
		Expires(1618888073).
		Nonce("b3c2a1").
		Tag("example").
		Parameter("custom", "value").
		MustBuild()

	// Marshal the definition
	marshaled, err := def.MarshalSFV()
	require.NoError(t, err, "MarshalSFV should succeed")

	// Should be an InnerList with components and parameters
	t.Logf("Marshaled definition: %s", string(marshaled))

	// Parse it to verify it's valid SFV
	result, err := input.Parse([]byte(`test=` + string(marshaled)))
	require.NoError(t, err, "Should be able to parse marshaled definition")
	require.Equal(t, 1, result.Len(), "Should have one definition")
}

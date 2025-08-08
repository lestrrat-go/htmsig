package component_test

import (
	"testing"

	"github.com/lestrrat-go/htmsig/component"
	"github.com/stretchr/testify/require"
)

func TestComponent(t *testing.T) {
	t.Run("Simple component", func(t *testing.T) {
		comp := component.New("@method")
		require.Equal(t, "@method", comp.Name())
		require.Empty(t, comp.Parameters())
		encoded, err := comp.MarshalSFV()
		require.NoError(t, err)
		require.Equal(t, `"@method"`, string(encoded))
	})

	t.Run("Component with boolean parameter", func(t *testing.T) {
		comp := component.New("@method").WithParameter("req", true)
		require.Equal(t, "@method", comp.Name())
		require.True(t, comp.HasParameter("req"))

		var reqVal bool
		require.NoError(t, comp.GetParameter("req", &reqVal))
		require.True(t, reqVal)
		encoded, err := comp.MarshalSFV()
		require.NoError(t, err)
		require.Equal(t, `"@method";req`, string(encoded))
	})

	t.Run("Component with string parameter", func(t *testing.T) {
		comp := component.New("@query-param").WithParameter("name", "Pet")
		require.Equal(t, "@query-param", comp.Name())
		require.True(t, comp.HasParameter("name"))
		var nameVal string
		require.NoError(t, comp.GetParameter("name", &nameVal))
		require.Equal(t, "Pet", nameVal)
		encoded, err := comp.MarshalSFV()
		require.NoError(t, err)
		require.Equal(t, `"@query-param";name="Pet"`, string(encoded))
	})

	t.Run("Component with multiple parameters", func(t *testing.T) {
		comp := component.New("content-type").
			WithParameter("req", true).
			WithParameter("sf", true)
		require.Equal(t, "content-type", comp.Name())
		require.True(t, comp.HasParameter("req"))
		require.True(t, comp.HasParameter("sf"))
		var reqVal, sfVal bool
		require.NoError(t, comp.GetParameter("req", &reqVal))
		require.NoError(t, comp.GetParameter("sf", &sfVal))
		require.True(t, reqVal)
		require.True(t, sfVal)

		// String representation should contain both parameters
		encoded, err := comp.MarshalSFV()
		require.NoError(t, err)
		str := string(encoded)
		require.Contains(t, str, `"content-type"`)
		require.Contains(t, str, "req")
		require.Contains(t, str, "sf")
	})
}

func TestParseComponent(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected component.Identifier
		wantErr  bool
	}{
		{
			name:     "Simple quoted component",
			input:    `"@method"`,
			expected: component.New("@method"),
		},
		{
			name:     "Component with req parameter",
			input:    `"@method";req`,
			expected: component.New("@method").WithParameter("req", true),
		},
		{
			name:     "Component with string parameter",
			input:    `"@query-param";name="Pet"`,
			expected: component.New("@query-param").WithParameter("name", "Pet"),
		},
		{
			name:     "Component with multiple parameters",
			input:    `"content-type";req;sf`,
			expected: component.New("content-type").WithParameter("req", true).WithParameter("sf", true),
		},
		{
			name:    "Invalid component",
			input:   `@invalid;bad=`,
			wantErr: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			comp, err := component.Parse([]byte(tt.input))

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected.Name(), comp.Name())
			require.Equal(t, len(tt.expected.Parameters()), len(comp.Parameters()))

			for _, key := range tt.expected.Parameters() {
				var expectedValue, actualValue any
				require.NoError(t, tt.expected.GetParameter(key, &expectedValue))
				require.NoError(t, comp.GetParameter(key, &actualValue))
				require.Equal(t, expectedValue, actualValue, "Parameter %q should match", key)
			}
		})
	}
}

func TestComponentRoundTrip(t *testing.T) {
	testCases := []string{
		`"@method"`,
		`"@method";req`,
		`"@query-param";name="Pet"`,
		`"content-type";req;sf`,
	}

	for _, input := range testCases {
		t.Run(input, func(t *testing.T) {
			// Parse -> String should produce equivalent results
			comp, err := component.Parse([]byte(input))
			require.NoError(t, err)

			// Parse the string representation again
			encoded, err := comp.MarshalSFV()
			require.NoError(t, err)
			comp2, err := component.Parse(encoded)
			require.NoError(t, err)

			// Should be equivalent
			require.Equal(t, comp.Name(), comp2.Name())
			require.Equal(t, len(comp.Parameters()), len(comp2.Parameters()))

			for _, key := range comp.Parameters() {
				var value1, value2 any
				require.NoError(t, comp.GetParameter(key, &value1))
				require.NoError(t, comp2.GetParameter(key, &value2))
				require.Equal(t, value1, value2)
			}
		})
	}
}

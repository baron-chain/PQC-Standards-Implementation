package params

import "testing"

func TestMlKem512(t *testing.T) {
	p := MlKem512
	if p.K != 2 {
		t.Errorf("K = %d, want 2", p.K)
	}
	if p.ETA1 != 3 {
		t.Errorf("ETA1 = %d, want 3", p.ETA1)
	}
	if p.ETA2 != 2 {
		t.Errorf("ETA2 = %d, want 2", p.ETA2)
	}
	if p.DU != 10 {
		t.Errorf("DU = %d, want 10", p.DU)
	}
	if p.DV != 4 {
		t.Errorf("DV = %d, want 4", p.DV)
	}
	if p.EKSize != 800 {
		t.Errorf("EKSize = %d, want 800", p.EKSize)
	}
	if p.DKSize != 1632 {
		t.Errorf("DKSize = %d, want 1632", p.DKSize)
	}
	if p.CTSize != 768 {
		t.Errorf("CTSize = %d, want 768", p.CTSize)
	}
}

func TestMlKem768(t *testing.T) {
	p := MlKem768
	if p.K != 3 {
		t.Errorf("K = %d, want 3", p.K)
	}
	if p.ETA1 != 2 {
		t.Errorf("ETA1 = %d, want 2", p.ETA1)
	}
	if p.ETA2 != 2 {
		t.Errorf("ETA2 = %d, want 2", p.ETA2)
	}
	if p.DU != 10 {
		t.Errorf("DU = %d, want 10", p.DU)
	}
	if p.DV != 4 {
		t.Errorf("DV = %d, want 4", p.DV)
	}
	if p.EKSize != 1184 {
		t.Errorf("EKSize = %d, want 1184", p.EKSize)
	}
	if p.DKSize != 2400 {
		t.Errorf("DKSize = %d, want 2400", p.DKSize)
	}
	if p.CTSize != 1088 {
		t.Errorf("CTSize = %d, want 1088", p.CTSize)
	}
}

func TestMlKem1024(t *testing.T) {
	p := MlKem1024
	if p.K != 4 {
		t.Errorf("K = %d, want 4", p.K)
	}
	if p.ETA1 != 2 {
		t.Errorf("ETA1 = %d, want 2", p.ETA1)
	}
	if p.ETA2 != 2 {
		t.Errorf("ETA2 = %d, want 2", p.ETA2)
	}
	if p.DU != 11 {
		t.Errorf("DU = %d, want 11", p.DU)
	}
	if p.DV != 5 {
		t.Errorf("DV = %d, want 5", p.DV)
	}
	if p.EKSize != 1568 {
		t.Errorf("EKSize = %d, want 1568", p.EKSize)
	}
	if p.DKSize != 3168 {
		t.Errorf("DKSize = %d, want 3168", p.DKSize)
	}
	if p.CTSize != 1568 {
		t.Errorf("CTSize = %d, want 1568", p.CTSize)
	}
}

func TestEncapsulationKeySizes(t *testing.T) {
	// EKSize = 384*k + 32 per FIPS 203
	tests := []struct {
		name string
		p    ParameterSet
	}{
		{"ML-KEM-512", MlKem512},
		{"ML-KEM-768", MlKem768},
		{"ML-KEM-1024", MlKem1024},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want := 384*tc.p.K + 32
			if tc.p.EKSize != want {
				t.Errorf("EKSize = %d, want 384*%d+32 = %d", tc.p.EKSize, tc.p.K, want)
			}
		})
	}
}

func TestDecapsulationKeySizes(t *testing.T) {
	// DKSize = 768*k + 96 per FIPS 203
	tests := []struct {
		name string
		p    ParameterSet
	}{
		{"ML-KEM-512", MlKem512},
		{"ML-KEM-768", MlKem768},
		{"ML-KEM-1024", MlKem1024},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want := 768*tc.p.K + 96
			if tc.p.DKSize != want {
				t.Errorf("DKSize = %d, want 768*%d+96 = %d", tc.p.DKSize, tc.p.K, want)
			}
		})
	}
}

func TestCiphertextSizes(t *testing.T) {
	// CTSize = 32*(du*k + dv) per FIPS 203
	tests := []struct {
		name string
		p    ParameterSet
	}{
		{"ML-KEM-512", MlKem512},
		{"ML-KEM-768", MlKem768},
		{"ML-KEM-1024", MlKem1024},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want := 32 * (tc.p.DU*tc.p.K + tc.p.DV)
			if tc.p.CTSize != want {
				t.Errorf("CTSize = %d, want 32*(%d*%d+%d) = %d", tc.p.CTSize, tc.p.DU, tc.p.K, tc.p.DV, want)
			}
		})
	}
}

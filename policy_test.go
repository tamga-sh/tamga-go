package tamga

import "testing"

func TestEffectiveOverageStrategy_DenyAccessDefaultMapsToNoOverage(t *testing.T) {
	if got := EffectiveOverageStrategy("DENY_ACCESS"); got != OverageNone {
		t.Errorf("EffectiveOverageStrategy(\"DENY_ACCESS\") = %v, want %v", got, OverageNone)
	}
}

func TestEffectiveResurrectionStrategy_NoResurrectionDefaultMapsToNoRevive(t *testing.T) {
	if got := EffectiveResurrectionStrategy("NO_RESURRECTION"); got != HeartbeatResurrectionNone {
		t.Errorf("EffectiveResurrectionStrategy(\"NO_RESURRECTION\") = %v, want %v", got, HeartbeatResurrectionNone)
	}
}

func TestEffectiveOverageStrategy_PassthroughForAll5RealVariants(t *testing.T) {
	variants := []OverageStrategy{OverageNone, Overage125x, Overage15x, Overage2x, OverageAlwaysAllow}
	if len(variants) != 5 {
		t.Fatalf("len(variants) = %d, want 5", len(variants))
	}
	for _, v := range variants {
		if got := EffectiveOverageStrategy(string(v)); got != v {
			t.Errorf("EffectiveOverageStrategy(%q) = %v, want %v", v, got, v)
		}
	}
}

func TestEffectiveResurrectionStrategy_PassthroughForAll7RealVariants(t *testing.T) {
	variants := []HeartbeatResurrectionStrategy{
		HeartbeatResurrectionNone, HeartbeatResurrection1Min, HeartbeatResurrection2Min,
		HeartbeatResurrection5Min, HeartbeatResurrection10Min, HeartbeatResurrection15Min,
		HeartbeatResurrectionAlways,
	}
	if len(variants) != 7 {
		t.Fatalf("len(variants) = %d, want 7", len(variants))
	}
	for _, v := range variants {
		if got := EffectiveResurrectionStrategy(string(v)); got != v {
			t.Errorf("EffectiveResurrectionStrategy(%q) = %v, want %v", v, got, v)
		}
	}
}

func TestOverageStrategy_Allows(t *testing.T) {
	tests := []struct {
		name     string
		strategy OverageStrategy
		count    int64
		max      int64
		want     bool
	}{
		{"no_overage_at_max", OverageNone, 10, 10, true},
		{"no_overage_over_max", OverageNone, 11, 10, false},
		{"1_25x_within", Overage125x, 12, 10, true},
		{"1_25x_over", Overage125x, 13, 10, false},
		{"1_5x_within", Overage15x, 15, 10, true},
		{"2x_within", Overage2x, 20, 10, true},
		{"always_allow_huge_count", OverageAlwaysAllow, 9999, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.strategy.Allows(tt.count, tt.max); got != tt.want {
				t.Errorf("%v.Allows(%d, %d) = %v, want %v", tt.strategy, tt.count, tt.max, got, tt.want)
			}
		})
	}
}

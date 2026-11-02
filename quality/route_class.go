// Package quality computes a continuous, multi-dimensional health
// score for an aether session. The score is the single source of
// truth read by the multipath routing layer, the adaptive liveness
// loop, and any other subsystem that needs to ask "is this connection
// any good right now?".
//
//   - Score range [0, 1] — continuous, smooth, no cliffs that cause
//     state-machine churn in consumers.
//   - Eight independent components combined via weighted geometric
//     mean: RTT health, RTT trend, loss, jitter, reorder, throughput,
//     reliability, stability. Any one bad signal pulls the aggregate
//     down. Multiplicative AgeGrace and FailurePenalty gates can
//     drive the result to zero independent of the components — a
//     brand-new session reads as 0 until grace lifts; a path with
//     several consecutive close-with-error events reads near zero
//     until the failures decay out.
//   - Route-class aware: each path is normalised against the expected
//     RTT band for its class (same-region / cross-region / inter-
//     continental). A 250 ms cross-region path scores like a 5 ms
//     same-region path when both are healthy for their kind, instead
//     of being permanently demoted by a fleet-wide static threshold.
//   - Region-affinity bonus is applied at dispatch time
//     (DispatchRank), not at score-computation time. A slow-but-
//     healthy cross-region path keeps a high quality score; the
//     dispatch layer picks same-region first when both exist.
//   - Trend-aware: the RTT component factors in the rate of change
//     of SRTT, so a path with rising RTT scores lower than one with
//     stable RTT at the same instantaneous value — an early-warning
//     signal that lets dispatch shift before things break.
package quality

import (
	"strings"
	"time"
)

// RouteClass categorizes a path by its geographic span. Sets the expected
// RTT band against which the path's measured RTT is normalized — without
// this, cross-region paths can never score well no matter how healthy they
// actually are.
type RouteClass int

const (
	// RouteUnknown is the default before classification. Treated like
	// CrossRegion for safety (lenient RTT band) so unclassified paths
	// don't get punished for not being known same-region.
	RouteUnknown RouteClass = iota

	// RouteSameRegion is two endpoints in the same Fly region (or any
	// other deployment where the local datacenter assumption holds).
	// Expected RTT band: 1–10 ms.
	RouteSameRegion

	// RouteCrossRegion is two endpoints in different regions on the
	// same continent (e.g. iad ↔ lax, syd ↔ akl). Expected RTT band:
	// 50–150 ms.
	RouteCrossRegion

	// RouteInterContinental is two endpoints on different continents
	// (e.g. iad ↔ syd, fra ↔ sjc). Expected RTT band: 150–400 ms.
	RouteInterContinental
)

// String returns a stable label suitable for log lines and metric tags.
func (r RouteClass) String() string {
	switch r {
	case RouteSameRegion:
		return "same-region"
	case RouteCrossRegion:
		return "cross-region"
	case RouteInterContinental:
		return "inter-continental"
	default:
		return "unknown"
	}
}

// ExpectedRTT returns the *median* RTT the route class is expected to
// produce when healthy. Used as the 50% mark of the score's RTT sigmoid —
// not a hard threshold. Set conservatively (toward the upper end of
// each band) so naturally noisy paths don't routinely score low.
func (r RouteClass) ExpectedRTT() time.Duration {
	switch r {
	case RouteSameRegion:
		return 5 * time.Millisecond
	case RouteCrossRegion:
		return 100 * time.Millisecond
	case RouteInterContinental, RouteUnknown:
		return 250 * time.Millisecond
	default:
		return 250 * time.Millisecond
	}
}

// AcceptableRTT returns the upper end of the expected band for this class.
// At AcceptableRTT the RTT component (rttHealth) scores ~0.5; at
// 2×AcceptableRTT it drops to ~0.1 — a logistic calibrated per class rather
// than a cliff at a multiple of ExpectedRTT, because the aggregate score
// is what the multipath dispatch layer ranks paths on (DispatchRank) and a
// step in it would flip that choice back and forth around one RTT value.
func (r RouteClass) AcceptableRTT() time.Duration {
	switch r {
	case RouteSameRegion:
		return 30 * time.Millisecond
	case RouteCrossRegion:
		return 200 * time.Millisecond
	case RouteInterContinental, RouteUnknown:
		return 500 * time.Millisecond
	default:
		return 500 * time.Millisecond
	}
}

// ClassifyRegions returns the RouteClass for an endpoint pair given each
// side's region tag. Region tags are Fly's three-letter region codes
// (e.g. "syd", "iad", "fra"). Unknown or empty regions yield RouteUnknown.
//
// The continent map is intentionally narrow — only the regions
// regionContinent lists. Adding a region requires adding a row; a region
// absent from the map classifies as RouteUnknown (the !lok || !rok return
// below), which takes RouteInterContinental's lenient RTT thresholds
// (components.go) and a lower affinity rank (score.go), so a missing entry
// under-promotes a path, never over-promotes it.
func ClassifyRegions(local, remote string) RouteClass {
	local = strings.ToLower(strings.TrimSpace(local))
	remote = strings.ToLower(strings.TrimSpace(remote))
	if local == "" || remote == "" {
		return RouteUnknown
	}
	if local == remote {
		return RouteSameRegion
	}

	lc, lok := regionContinent[local]
	rc, rok := regionContinent[remote]
	if !lok || !rok {
		return RouteUnknown
	}
	if lc == rc {
		return RouteCrossRegion
	}
	return RouteInterContinental
}

// regionContinent is the continent assignment for each Fly region the
// table knows. Adding a region requires adding a row; a region absent from
// the map classifies as RouteUnknown, which takes RouteInterContinental's RTT
// thresholds and a lower affinity rank (score.go), so a missing row
// under-promotes a path.
var regionContinent = map[string]string{
	// North America
	"iad": "na", // Ashburn, Virginia
	"ord": "na", // Chicago
	"sjc": "na", // San Jose
	"lax": "na", // Los Angeles
	"sea": "na", // Seattle
	"yyz": "na", // Toronto
	"yul": "na", // Montreal

	// Europe
	"fra": "eu", // Frankfurt
	"ams": "eu", // Amsterdam
	"lhr": "eu", // London
	"cdg": "eu", // Paris
	"mad": "eu", // Madrid
	"arn": "eu", // Stockholm

	// Asia / Pacific
	"syd": "oc", // Sydney
	"sin": "as", // Singapore
	"nrt": "as", // Tokyo
	"hkg": "as", // Hong Kong
	"bom": "as", // Mumbai

	// South America
	"gru": "sa", // São Paulo
	"scl": "sa", // Santiago

	// Africa
	"jnb": "af", // Johannesburg
}

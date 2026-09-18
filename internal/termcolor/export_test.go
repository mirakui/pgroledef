package termcolor

// The environment half of Detect is exported for the tests, so the opt-out and
// force variables can be covered without a controlling terminal.
var (
	EnvAllowsColor = envAllowsColor
	EnvForcesColor = envForcesColor
	IsTerminal     = isTerminal
)

package engine

import "github.com/mazdakn/fwsim/internal/model"

type Result struct {
	EnforcedBy *model.Rule
	Trace      []*model.Rule
}

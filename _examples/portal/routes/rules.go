package routes

import (
	"example/portal"
	"example/portal/views"

	"azugo.io/auth"
	"azugo.io/auth/session"

	"azugo.io/azugo"
	"azugo.io/templ"
	"github.com/goccy/go-json"
)

// rulesPage renders the portal rules for a login held at the rules step.
func (r *router) rulesPage(ctx *azugo.Context) {
	returnTo := ""
	if v := ctx.Query.StringOptional("return_to"); v != nil {
		returnTo = *v
	}

	templ.Render(ctx, views.Rules(portal.RulesVersion, returnTo, ctx.Flash.FieldErrorFor("accept")))
}

// acceptRules submits the acceptance to the pending rules step.
func (r *router) acceptRules(ctx *azugo.Context) {
	req := auth.StepRequest{
		Token:   r.Auth().ReadSessionToken(ctx),
		Name:    portal.StepRules,
		BaseURL: ctx.BaseURL(),
		IP:      ctx.IP().String(),
	}

	if v := ctx.Form.StringOptional("return_to"); v != nil {
		req.ReturnTo = *v
	}

	// An unchecked box submits no version, which the step refuses.
	var in struct {
		Version string `json:"version"`
	}

	if v := ctx.Form.StringOptional("accept"); v != nil && *v != "" {
		if version := ctx.Form.StringOptional("version"); version != nil {
			in.Version = *version
		}
	}

	req.Payload, _ = json.Marshal(in)

	res, err := r.Auth().ResolveStep(ctx, req)
	if err != nil {
		if r.fatal(ctx, err, req.ReturnTo) {
			return
		}

		ctx.Flash.FieldError("accept", errorMessage(err, "Could not accept the rules."))
		ctx.Redirect(pageURL("/rules", req.ReturnTo))

		return
	}

	if res.Status == session.StatusPendingStep && res.Step == portal.StepRules {
		message, _ := res.Data["error"].(string)
		ctx.Flash.FieldError("accept", message)
	}

	r.finishStep(ctx, res, req.ReturnTo)
}

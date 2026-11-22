// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"strings"

	"shepherd/internal/backends"
)

// The OpenAPI description of the router API (api_v1.go), built from the
// route table rather than written beside it.

type schema = map[string]any

func str(desc string) schema     { return schema{"type": "string", "description": desc} }
func boolean(desc string) schema { return schema{"type": "boolean", "description": desc} }
func integer(desc string) schema { return schema{"type": "integer", "description": desc} }
func timeOf(desc string) schema {
	return schema{"type": "string", "format": "date-time", "description": desc}
}
func object(required []string, props schema) schema {
	out := schema{"type": "object", "properties": props}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}
func enum(desc string, vals ...string) schema {
	return schema{"type": "string", "description": desc, "enum": vals}
}

// v1Schemas are the shapes the API speaks. Keep them in step with the
// structs in api_v1.go; TestTheOpenAPIDocumentMatchesWhatIsServed checks
// that every field a call returns is described here.
func v1Schemas() schema {
	caps := []string{}
	for _, c := range []backends.Capability{
		backends.CapDevices, backends.CapFlows, backends.CapAlarms, backends.CapRules, backends.CapRuleWrite,
		backends.CapRuleCreate, backends.CapDeviceRename, backends.CapDeviceBlock, backends.CapAlarmDismiss,
		backends.CapGroups, backends.CapGroupWrite, backends.CapSchedule,
	} {
		caps = append(caps, string(c))
	}
	return schema{
		"Error": object([]string{"error", "code"}, schema{
			"error": str("What went wrong, in words."),
			"code": enum("A stable code for the same.", "not_connected", "unsupported", "read_only", "invalid",
				"not_found", "rate_limited", "credential_refused", "router_error"),
		}),
		"Ok": object([]string{"ok"}, schema{"ok": boolean("Always true.")}),
		"Router": object([]string{"connected", "capabilities"}, schema{
			"connected": boolean("Whether a router or firewall is connected and being read."),
			"product":   str(`Which product: "firewalla" or "unifi".`),
			"read_only": boolean("True while Allow changes is off: every write is refused."),
			"capabilities": schema{"type": "array", "description": "What this product can do right now. A write capability is absent while read_only is true.",
				"items": schema{"type": "string", "enum": caps}},
			"last_read": timeOf("When the router was last read successfully."),
			"errors": schema{"type": "object", "description": "For each resource whose last read failed, why.",
				"additionalProperties": schema{"type": "string"}},
		}),
		"Device": object([]string{"mac", "name", "online", "blocked"}, schema{
			"mac":       str("Lower-case hexadecimal, no separators. Identifies the device in every call."),
			"name":      str("The router's name for the device."),
			"ip":        str("Its current address."),
			"vendor":    str("The maker, from the MAC address."),
			"online":    boolean("Whether the router has seen it recently."),
			"group":     str("The device group it is in, by name."),
			"network":   str("The network it is on."),
			"blocked":   boolean("Whether Shepherd has cut it off from the network."),
			"name_from": enum("Where the name came from, when the product can tell.", "typed", "learned"),
		}),
		"DevicePatch": object(nil, schema{
			"name":    str("A new name. Needs devices:rename."),
			"group":   str("The group to move it into, by name; it is made if missing. Empty takes it out of its group. Needs groups:write."),
			"blocked": boolean("True cuts it off from the network, false restores it. Needs devices:block."),
		}),
		"Group": object([]string{"id", "name", "devices"}, schema{
			"id": str("The router's own ID for the group."), "name": str("Its name."),
			"devices": integer("How many devices are in it."),
		}),
		"Rule": object([]string{"id", "action", "target_type", "target", "dns_only", "paused"}, schema{
			"id":          str("The router's ID for the rule."),
			"action":      str(`"block", "allow", or a product's own action such as "timelimit".`),
			"target_type": str(`What the rule matches: "domain", "ip", "net", "category", "app", "region", "targetlist", or a product's own.`),
			"target":      str("The thing matched."),
			"dns_only":    boolean("True when the rule acts on name lookups only."),
			"scope_type":  enum("What the rule applies to; absent for every device.", "device", "group", "user", "network"),
			"scope":       str("The device's MAC, or the group, user or network."),
			"name":        str("The rule's name, where the product names rules."),
			"paused":      boolean("Whether the rule is switched off."),
			"notes":       str("Free text."),
			"schedule":    str("When the router itself applies the rule, in words."),
			"created":     timeOf("When it was made."),
		}),
		"RuleCreate": object([]string{"action", "target_type", "target"}, schema{
			"action":            enum("What to do.", "block", "allow"),
			"target_type":       enum("What to match.", backends.TargetTypes...),
			"target":            str("The domain, address, network, category, app, region or list."),
			"block_connections": boolean("For a domain, category, app or list: act on connections as well as name lookups."),
			"scope_type":        enum("Limit the rule; omit for every device.", backends.ScopeTypes...),
			"scope":             str("The device's MAC, or the group, user or network."),
			"notes":             str("Free text."),
			"box":               str("Limit the rule to one box, for a product with several."),
		}),
		"RulePatch": object([]string{"paused"}, schema{"paused": boolean("True pauses the rule, false resumes it.")}),
		"Alarm": object([]string{"id", "type", "message"}, schema{
			"id": str("The router's ID for the alarm."), "box": str("The box it is on, for a product with several."),
			"type": str("The kind of alarm, in the product's words."), "message": str("What happened."),
			"time": timeOf("When."), "mac": str("The device concerned."), "device": str("Its name."),
			"domain": str("The remote name concerned."),
		}),
		"Flow": object([]string{"time", "outbound", "blocked", "download_bytes", "upload_bytes"}, schema{
			"time": timeOf("When the request was made."), "mac": str("The device."), "device": str("Its name."),
			"device_ip": str("Its address."), "domain": str("The name it asked for, when known."),
			"remote_ip": str("Where the traffic went."), "protocol": str(`"tcp" or "udp".`),
			"outbound": boolean("True for a connection the device opened."), "blocked": boolean("Whether the router blocked it."),
			"download_bytes": integer("Bytes received."), "upload_bytes": integer("Bytes sent."),
			"country": str("ISO 3166-1 alpha-2 code of the remote end."), "category": str("The product's category for the destination."),
			"count": integer("How many connections the record stands for."),
		}),
	}
}

func ref(name string) schema { return schema{"$ref": "#/components/schemas/" + name} }

func jsonBody(s schema) schema { return schema{"application/json": schema{"schema": s}} }

// v1OpenAPI is the whole document.
func v1OpenAPI(version string) schema {
	if version == "" {
		version = "dev"
	}
	paths := schema{}
	failures := schema{"description": "The call was refused or failed; see code.", "content": jsonBody(ref("Error"))}
	for _, rt := range v1Routes() {
		op := schema{
			"summary":     rt.summary,
			"operationId": operationID(rt),
			"responses":   schema{"default": failures},
		}
		if rt.needs != "" {
			op["description"] = "Needs the `" + string(rt.needs) + "` capability (see GET /api/v1/router)."
		}
		var params []schema
		for _, p := range rt.params {
			params = append(params, schema{"name": p.name, "in": p.in, "required": p.required,
				"description": p.description, "schema": schema{"type": "string"}})
		}
		if len(params) > 0 {
			op["parameters"] = params
		}
		if rt.body != "" {
			op["requestBody"] = schema{"required": true, "content": jsonBody(ref(rt.body))}
		}
		reply := ref(rt.reply)
		if rt.list != "" {
			props := schema{rt.list: schema{"type": "array", "items": ref(rt.reply)}}
			if rt.list == "flows" {
				props["next"] = str("Pass as cursor for the next page; empty on the last.")
			}
			reply = object([]string{rt.list}, props)
		}
		status := "200"
		if rt.method == "POST" {
			status = "201"
		}
		op["responses"].(schema)[status] = schema{"description": "OK", "content": jsonBody(reply)}
		item, _ := paths[rt.path].(schema)
		if item == nil {
			item = schema{}
			paths[rt.path] = item
		}
		item[strings.ToLower(rt.method)] = op
	}
	return schema{
		"openapi": "3.1.0",
		"info": schema{
			"title":   "Shepherd router API",
			"version": version,
			"description": "One API over whatever router or firewall Shepherd is connected to. The calls are the same for every product; " +
				"GET /api/v1/router says which of them the connected one can serve. Send the portal token as a bearer token, " +
				"and the header X-Shepherd: 1 on every call that changes something.",
			"license": schema{"name": "AGPL-3.0-or-later", "identifier": "AGPL-3.0-or-later"},
		},
		"servers":  []schema{{"url": "/", "description": "This Shepherd"}},
		"security": []schema{{"portalToken": []string{}}},
		"paths":    paths,
		"components": schema{
			"schemas": v1Schemas(),
			"securitySchemes": schema{"portalToken": schema{"type": "http", "scheme": "bearer",
				"description": "The portal token (the file portal-token in Shepherd's data directory)."}},
		},
	}
}

// operationID is a stable name for a call, for generated clients:
// "getDevices", "patchDevicesMac", "deleteRulesId".
func operationID(rt v1Route) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(rt.method))
	for _, part := range strings.Split(strings.TrimPrefix(rt.path, "/api/v1/"), "/") {
		part = strings.Trim(part, "{}")
		if part != "" {
			b.WriteString(strings.ToUpper(part[:1]) + part[1:])
		}
	}
	return b.String()
}

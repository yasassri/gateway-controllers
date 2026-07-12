/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package basicratelimit

import (
	"context"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	ratelimit "github.com/wso2/gateway-controllers/policies/advanced-ratelimit"
)

// BasicRateLimitPolicy provides a simplified rate limiting policy that delegates
// to the core ratelimit policy. It uses routename as the rate limit key and
// does not support cost extraction or multi-quota configurations.
type BasicRateLimitPolicy struct {
	delegate policy.Policy
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	// Transform simple limits to full ratelimit config
	rlParams := transformToRatelimitParams(params, metadata)

	// Create the delegate ratelimit policy
	delegate, err := ratelimit.GetPolicy(metadata, rlParams)
	if err != nil {
		return nil, err
	}

	return &BasicRateLimitPolicy{delegate: delegate}, nil
}


func (p *BasicRateLimitPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// transformToRatelimitParams converts the simple limits array to a full ratelimit
// quota configuration with routename key extraction, and passes through system
// parameters (algorithm, backend, redis, memory, local).
func transformToRatelimitParams(params map[string]interface{}, metadata policy.PolicyMetadata) map[string]interface{} {
	limits, _ := params["limits"].([]interface{})

	// basic-ratelimit uses `requests` while advanced-ratelimit expects `limit`.
	// Translate each limit entry before delegating.
	transformedLimits := make([]interface{}, 0, len(limits))
	for _, entry := range limits {
		limitMap, ok := entry.(map[string]interface{})
		if !ok {
			transformedLimits = append(transformedLimits, entry)
			continue
		}

		translated := make(map[string]interface{}, len(limitMap))
		for k, v := range limitMap {
			translated[k] = v
		}

		if requests, ok := translated["requests"]; ok {
			translated["limit"] = requests
			delete(translated, "requests")
		}

		transformedLimits = append(transformedLimits, translated)
	}

	keyExtractorType := "routename"
	if metadata.AttachedTo == policy.LevelAPI {
		keyExtractorType = "apiname"
	}

	rlParams := map[string]interface{}{
		"quotas": []interface{}{
			map[string]interface{}{
				"name":   "default",
				"limits": transformedLimits,
				"keyExtraction": []interface{}{
					map[string]interface{}{
						"type": keyExtractorType,
					},
				},
			},
		},
	}

	// Pass through system parameters
	if algorithm, ok := params["algorithm"]; ok {
		rlParams["algorithm"] = algorithm
	}
	if backend, ok := params["backend"]; ok {
		rlParams["backend"] = backend
	}
	if redis, ok := params["redis"]; ok {
		rlParams["redis"] = redis
	}
	if memory, ok := params["memory"]; ok {
		rlParams["memory"] = memory
	}
	if local, ok := params["local"]; ok {
		rlParams["local"] = local
	}

	return rlParams
}

// OnRequestHeaders delegates to the core ratelimit policy's OnRequestHeaders method if available.
func (p *BasicRateLimitPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext,
	params map[string]interface{},
) policy.RequestHeaderAction {
	type requestHeaderPolicer interface {
		OnRequestHeaders(context.Context, *policy.RequestHeaderContext, map[string]interface{}) policy.RequestHeaderAction
	}
	if rl, ok := p.delegate.(requestHeaderPolicer); ok {
		return rl.OnRequestHeaders(ctx, reqCtx, params)
	}
	return policy.UpstreamRequestHeaderModifications{}
}

// OnResponseHeaders delegates to the core ratelimit policy's OnResponseHeaders method if available.
func (p *BasicRateLimitPolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext,
	params map[string]interface{},
) policy.ResponseHeaderAction {
	type responseHeaderPolicer interface {
		OnResponseHeaders(context.Context, *policy.ResponseHeaderContext, map[string]interface{}) policy.ResponseHeaderAction
	}
	if rl, ok := p.delegate.(responseHeaderPolicer); ok {
		return rl.OnResponseHeaders(ctx, respCtx, params)
	}
	return policy.DownstreamResponseHeaderModifications{}
}

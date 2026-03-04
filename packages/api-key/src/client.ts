import type { BetterAuthClientPlugin } from "@better-auth/core";
import type { DBFieldAttribute } from "@better-auth/core/db";
import type { BetterAuthOptions, BetterAuthPlugin } from "better-auth/types";
import type { apiKey } from ".";
import { API_KEY_ERROR_CODES } from "./error-codes";
import type { ApiKeyOptions } from "./types";

export * from "./error-codes";

interface ApiKeyClientOptions {
	schema?:
		| {
				apikey?: {
					additionalFields?: {
						[key: string]: DBFieldAttribute;
					};
				};
		  }
		| undefined;
}

export const apiKeyClient = <CO extends ApiKeyClientOptions>(
	options?: CO | undefined,
) => {
	return {
		id: "api-key",
		$InferServerPlugin: {} as ReturnType<typeof apiKey>,
		pathMethods: {
			"/api-key/create": "POST",
			"/api-key/delete": "POST",
			"/api-key/delete-all-expired-api-keys": "POST",
		},
		$ERROR_CODES: API_KEY_ERROR_CODES,
	} satisfies BetterAuthClientPlugin;
};

export const inferApiKeyAdditionalFields = <
	O extends {
		options: BetterAuthOptions;
	},
	S extends ApiKeyOptions["schema"] = undefined,
>(
	schema?: S | undefined,
) => {
	type FindById<
		T extends readonly BetterAuthPlugin[],
		TargetId extends string,
	> = Extract<T[number], { id: TargetId }>;

	type Auth = O extends { options: any } ? O : { options: { plugins: [] } };

	type ApiKeyPlugin = FindById<
		// @ts-expect-error
		Auth["options"]["plugins"],
		"api-key"
	>;

	type ExtractClientOnlyFields<T> = {
		[K in keyof T as T[K] extends { additionalFields: any } ? K : never]: T[K];
	};

	type Schema = O extends Object
		? O extends Exclude<ApiKeyOptions["schema"], undefined>
			? O
			: ApiKeyPlugin extends { options: { schema: infer S } }
				? S extends ApiKeyOptions["schema"]
					? ExtractClientOnlyFields<S>
					: undefined
				: undefined
		: undefined;
	return {} as undefined extends S ? Schema : S;
};

export type ApiKeyClientPlugin = ReturnType<typeof apiKeyClient>;

export type * from "./types";

/* mldsa-native portfolio ACVP registration definition.
 *
 * This file declares only the v1 pure/external validation surface.
 * License: see LICENSE in the pqc-acvp-iut-lab repository.
 */

#include "definition.h"
#include "definition_impl_common.h"

#define MLD_NATIVE_PARAMETER_SETS                                      \
	(DEF_ALG_ML_DSA_44 | DEF_ALG_ML_DSA_65 | DEF_ALG_ML_DSA_87)

static const struct def_algo_ml_dsa_caps mld_native_keygen_caps[] = { {
	.parameter_set = MLD_NATIVE_PARAMETER_SETS,
} };

static const struct def_algo_ml_dsa_caps mld_native_signature_caps[] = { {
	.parameter_set = MLD_NATIVE_PARAMETER_SETS,
	DEF_ALG_DOMAIN(.messagelength, 8, 65536, 8),
	DEF_ALG_DOMAIN(.contextlength, 0, 2040, 8),
} };

static const struct def_algo mld_native_pure_external[] = {
	{
		.type = DEF_ALG_TYPE_ML_DSA,
		.algo.ml_dsa = {
			.ml_dsa_mode = DEF_ALG_ML_DSA_MODE_KEYGEN,
			.capabilities.keygen = mld_native_keygen_caps,
			.capabilities_num = ARRAY_SIZE(mld_native_keygen_caps),
		},
	},
	{
		.type = DEF_ALG_TYPE_ML_DSA,
		.algo.ml_dsa = {
			.ml_dsa_mode = DEF_ALG_ML_DSA_MODE_SIGGEN,
			.capabilities.siggen = mld_native_signature_caps,
			.capabilities_num = ARRAY_SIZE(mld_native_signature_caps),
			.deterministic =
				DEF_ALG_ML_DSA_SIGGEN_NON_DETERMINISTIC |
				DEF_ALG_ML_DSA_SIGGEN_DETERMINISTIC,
			.interface = DEF_ALG_ML_DSA_INTERFACE_EXTERNAL,
			.external_mu = 0,
		},
	},
	{
		.type = DEF_ALG_TYPE_ML_DSA,
		.algo.ml_dsa = {
			.ml_dsa_mode = DEF_ALG_ML_DSA_MODE_SIGVER,
			.capabilities.sigver = mld_native_signature_caps,
			.capabilities_num = ARRAY_SIZE(mld_native_signature_caps),
			.interface = DEF_ALG_ML_DSA_INTERFACE_EXTERNAL,
			.external_mu = 0,
		},
	},
};

static struct def_algo_map mld_native_algo_map[] = {
	{
		SET_IMPLEMENTATION(mld_native_pure_external),
		.algo_name = "mldsa-native",
		.processor = "",
		.impl_name = "ML-DSA pure external",
		.impl_description =
			"mldsa-native portable C: FIPS 204 pure/external validation",
	},
};

ACVP_DEFINE_CONSTRUCTOR(mld_native_register)
static void mld_native_register(void)
{
	acvp_register_algo_map(mld_native_algo_map,
			       ARRAY_SIZE(mld_native_algo_map));
}

ACVP_EXTENSION(mld_native_algo_map)


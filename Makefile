.PHONY: mlkem-native-portable mlkem-native-arm64 mlkem-native-arm64-benchmark mldsa-native-portable mldsa-native-official-replay mldsa-native-completion

mlkem-native-portable:
	python3 tools/mlkem_native_build.py

mlkem-native-arm64:
	python3 tools/mlkem_native_arm64_build.py

mlkem-native-arm64-benchmark: mlkem-native-portable mlkem-native-arm64
	python3 tools/benchmark_mlkem_native.py \
		--portable-manifest evidence/build/mlkem-native-portable.json \
		--portable-build build/mlkem-native/portable-multilevel \
		--native-manifest evidence/build/mlkem-native-aarch64.json \
		--native-build build/mlkem-native/aarch64-native-multilevel \
		--output-dir build/mlkem-native/benchmark \
		--report evidence/benchmarks/mlkem-native-arm64.json

mldsa-native-portable:
	python3 tools/mldsa_native_build.py

mldsa-native-official-replay: mldsa-native-portable
	@source="$$(find .deps/mldsa-native/src -mindepth 1 -maxdepth 1 -type d | head -n 1)"; \
	$(MAKE) -C "$$source" OPT=0 ACVP_VERSION=v1.1.0.41 run_acvp; \
	PYTHONPATH=src python3 tools/replay_mldsa_official.py \
		--data-dir "$$source/test/acvp/.acvp-data/v1.1.0.41/files" \
		--bridge build/mldsa-native/portable-multilevel/mldsa_native_bridge \
		--manifest evidence/build/mldsa-native-portable.json \
		--report build/mldsa-native/official-replay.json

mldsa-native-completion:
	PYTHONPATH=src python3 tools/verify_mldsa_completion.py \
		--official-report evidence/reviews/mldsa-native-official-acvp.json \
		--report evidence/reviews/mldsa-native-completion.json

	# ---------------------------------------------------------------------------
	# CAT test harness - TEMPLATE. Inlined into out/cat_claims.vtc by tools/make_vtc.py.
	#
	# Contract with the generated client requests:
	#   * The token arrives as described by each test (header CTA-Common-Access-Token,
	#     cookie CAT, or query parameter CAT). Each request carries a cat-test-id header.
	#   * The harness MUST set resp.http.cat-result to exactly "accept" or "reject".
	#
	# Until the CAT verification code (VCC-1484 "service-side sub cat_verify()") is wired in
	# below, every test fails with cat-result "NOT-WIRED". That is deliberate: a harness that
	# echoes request headers would make every test pass without testing anything.
	#
	# The key table holds the TEST-ONLY key from keys/hs256-test-key.json.
	# ---------------------------------------------------------------------------
	pragma param no_backends true;

	table key_table STRING {
		"@@KID@@": "@@KEY_B64@@"
	}

	sub vcl_recv {
		error 200 "OK";
	}

	sub vcl_deliver {
		set resp.http.cat-test-id = req.http.cat-test-id;
		# >>> Replace this line with the CAT verification call(s) and set
		# >>> resp.http.cat-result to "accept" or "reject".
		set resp.http.cat-result = "NOT-WIRED";
	}

	sub vcl_error {
		set obj.http.Connection:Keep-Alive = "";
	}

// Copyright © 2019, Oracle and/or its affiliates.
package pkcs11

import (
	"reflect"
	"testing"

	"golang.org/x/net/context"
)

/*
* To run these tests, ensure you setup:
* 1. OCI SDK with your credentials. Refer to here:
*		https://docs.cloud.oracle.com/iaas/Content/API/Concepts/sdkconfig.htm
* 2. Go to ocikms folder: vault/vault/seal/ocikms
*		VAULT_OCIKMS_SEAL_KEY_ID="your-kms-key" VAULT_OCIKMS_CRYPTO_ENDPOINT="your-kms-crypto-endpoint" go test
 */

func TestWrapper(t *testing.T) {
	initSeal(t)
}

func TestWrapper_LifeCycle(t *testing.T) {
	s := initSeal(t)

	// Test Encrypt and Decrypt calls
	input := []byte("foo")
	swi, err := s.Encrypt(context.Background(), input, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	pt, err := s.Decrypt(context.Background(), swi, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	t.Logf("expected %s, got %s", input, pt)
	if !reflect.DeepEqual(input, pt) {
		t.Fatalf("expected %s, got %s", input, pt)
	}
}

func initSeal(t *testing.T) *Wrapper {
	// Skip tests if we are not running acceptance tests
	/*if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}*/
	s := NewWrapper(nil)
	_, err := s.SetConfig(nil)
	if err == nil {
		t.Fatal("expected error when Wrapper required values are not provided")
	}

	mockConfig := map[string]string{

		"lib":          "/usr/lib/softhsm/libsofthsm2.so",
		"key_label":    "piloupilou",
		"slot":         "105344715",
		"pin":          "123456",
		"generate_key": "f",
	}

	_, err = s.SetConfig(mockConfig)
	if err != nil {
		t.Fatalf("error setting seal config: %v", err)
	}

	return s
}

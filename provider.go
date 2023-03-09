// Copyright The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/initialize"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

const (
	apiVersion      = "externaldata.gatekeeper.sh/v1alpha1"
	defaultRekorURL = "https://rekor.sigstore.dev"
)

var (
	rekorClient         *client.Rekor
	fulcioRoots         *x509.CertPool
	fulcioIntermediates *x509.CertPool
	identities          []cosign.Identity
	skipTlogVerify      bool
	ignoreSCT           bool
)

func main() {
	fmt.Println("starting server...")
	http.HandleFunc("/validate", validate)

	// Init self-service TrustRoot if needed
	if os.Getenv("TUF_URL") != "" {
		mirror := os.Getenv("TUF_URL")
		fmt.Println("Starting to initialize the Trust root from", mirror)
		root := mirror + "/root.json"
		err := initialize.DoInitialize(context.Background(), root, mirror)
		if err != nil {
			panic(fmt.Sprintf("initializing selfhosted TrustRoot: %v", err))
		}
	}

	rekorURL := os.Getenv("REKOR_URL")
	if rekorURL == "" {
		rekorURL = defaultRekorURL
	}
	rc, err := rekor.NewClient(rekorURL)
	if err != nil {
		panic(fmt.Sprintf("creating Rekor client: %v", err))
	}
	rekorClient = rc

	roots, err := fulcio.GetRoots()
	if err != nil {
		panic(fmt.Sprintf("getting Fulcio root certs: %v", err))
	}
	fulcioRoots = roots

	intermediates, err := fulcio.GetIntermediates()
	if err != nil {
		panic(fmt.Sprintf("getting Fulcio intermediates certs: %v", err))
	}
	fulcioIntermediates = intermediates

	// Claims from Identity token to verify (compulsory when using keyless verifying)
	identities = []cosign.Identity{{
		Issuer:        os.Getenv("CERT_OIDC_ISSUER"),
		Subject:       os.Getenv("CERT_OIDC_SUBJECT"),
		IssuerRegExp:  os.Getenv("CERT_OIDC_ISSUER_REGEX"),
		SubjectRegExp: os.Getenv("CERT_OIDC_SUBJECT_REGEX"),
	}}

	skipTlogVerify, err = strconv.ParseBool(os.Getenv("SKIP_TLOG_VERIFY"))
	if err != nil {
		panic(fmt.Sprintf("wrong value type Bool for env SKIP_TLOG_VERIFY: %v", err))
	}

	ignoreSCT, err = strconv.ParseBool(os.Getenv("IGNORE_SCT"))
	if err != nil {
		panic(fmt.Sprintf("wrong value type Bool for env IGNORE_SCT: %v", err))
	}

	tlsKeyPath := os.Getenv("TLS_KEY_PATH")
	tlsCertPath := os.Getenv("TLS_CERT_PATH")

	srv := &http.Server{
		Addr:              ":8090",
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if err := srv.ListenAndServeTLS(tlsCertPath, tlsKeyPath); err != nil {
		panic(err)
	}
}

func validate(w http.ResponseWriter, req *http.Request) {
	// only accept POST requests
	if req.Method != http.MethodPost {
		sendResponse(nil, "only POST is allowed", w)
		return
	}

	// read request body
	requestBody, err := io.ReadAll(req.Body)
	if err != nil {
		sendResponse(nil, fmt.Sprintf("unable to read request body: %v", err), w)
		return
	}

	// parse request body
	var providerRequest externaldata.ProviderRequest
	err = json.Unmarshal(requestBody, &providerRequest)
	if err != nil {
		sendResponse(nil, fmt.Sprintf("unable to unmarshal request body: %v", err), w)
		return
	}

	results := make([]externaldata.Item, 0)

	ctx := req.Context()
	// Options connecting to registry
	ro := options.RegistryOptions{
		KubernetesKeychain: true, // Allow to support getting credential with some other registry providers
		AllowInsecure:      true,
	}
	co, err := ro.ClientOpts(ctx)
	if err != nil {
		sendResponse(nil, fmt.Sprintf("ERROR: %v", err), w)
		return
	}

	checkOpt := &cosign.CheckOpts{
		Identities:         identities,
		RekorClient:        rekorClient,
		RegistryClientOpts: co,
		RootCerts:          fulcioRoots,
		IntermediateCerts:  fulcioIntermediates,
		ClaimVerifier:      cosign.SimpleClaimVerifier,
	}

	// Tlog verifying if enabled
	if skipTlogVerify {
		checkOpt.IgnoreSCT = true
	} else {
		checkOpt.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
		if err != nil {
			sendResponse(nil, fmt.Sprintf("getting Rekor public keys: %v", err), w)
			return
		}
	}

	// CTlog verifying if enabled
	if !ignoreSCT {
		checkOpt.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
		if err != nil {
			sendResponse(nil, fmt.Sprintf("getting ctlog public keys: %v", err), w)
			return
		}
	}

	// iterate over all keys
	for _, key := range providerRequest.Request.Keys {
		fmt.Println("verify signature for:", key)
		ref, err := name.ParseReference(key)
		if err != nil {
			sendResponse(nil, fmt.Sprintf("ERROR (ParseReference(%q)): %v", key, err), w)
			return
		}

		checkedSignatures, bundleVerified, err := cosign.VerifyImageSignatures(ctx, ref, checkOpt)

		if err != nil {
			fmt.Println(err)
			sendResponse(nil, fmt.Sprintf("VerifyImageSignatures: %v", err), w)
			return
		}

		listSANS := make([]string, 0)
		if bundleVerified {
			fmt.Println("signature verified for:", key)
			fmt.Printf("%d number of valid signatures found for %s, found signatures: %v\n", len(checkedSignatures), key, checkedSignatures)

			for _, sig := range checkedSignatures {
				cert, err := sig.Cert()
				if err != nil {
					fmt.Println(err)
				}
				sans := getSubjectAlternateNames(cert)
				fmt.Printf("SANs from %s: %v", key, sans)
				listSANS = append(listSANS, sans...)
			}

			results = append(results, externaldata.Item{
				Key:   key,
				Value: listSANS,
				// Value: key + "_valid",
			})
		} else {
			fmt.Printf("no valid signatures found for: %s\n", key)
			results = append(results, externaldata.Item{
				Key:   key,
				Error: key + "_invalid",
			})
		}
	}

	sendResponse(&results, "", w)
}

// sendResponse sends back the response to Gatekeeper.
func sendResponse(results *[]externaldata.Item, systemErr string, w http.ResponseWriter) {
	response := externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       "ProviderResponse",
	}

	if results != nil {
		response.Response.Items = *results
	} else {
		response.Response.SystemError = systemErr
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		panic(err)
	}
}

func getSubjectAlternateNames(cert *x509.Certificate) []string {
	sans := []string{}
	sans = append(sans, cert.DNSNames...)
	sans = append(sans, cert.EmailAddresses...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}
	// ignore error if there's no OtherName SAN
	otherName, _ := cryptoutils.UnmarshalOtherNameSAN(cert.Extensions)
	if len(otherName) > 0 {
		sans = append(sans, otherName)
	}
	return sans
}

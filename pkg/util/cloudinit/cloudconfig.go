// (C) Copyright IBM Corp. 2022.
// SPDX-License-Identifier: Apache-2.0

package cloudinit

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"text/template"

	"gopkg.in/yaml.v3"
)

const (
	DefaultAuthfileSrcPath = "/root/containers/auth.json"
	// image-rs fixed dst path for support at the agent, we convert it explictly to the resources file format
	// e.g. https://github.com/confidential-containers/guest-components/blob/main/attestation-agent/kbc/src/offline_fs_kbc/aa-offline_fs_kbc-resources.json
	DefaultAuthfileDstPath = "/etc/aa-offline_fs_kbc-resources.json"
	DefaultAuthfileLimit   = 12288 // TODO: use a whole userdata limit mechanism instead of limiting authfile
)

// https://cloudinit.readthedocs.io/en/latest/topics/format.html#cloud-config-data

type CloudConfigGenerator interface {
	Generate() (string, error)
}

type CloudConfig struct {
	WriteFiles []WriteFile `yaml:"write_files"`
}

// https://cloudinit.readthedocs.io/en/latest/topics/modules.html#write-files
type WriteFile struct {
	Path        string `yaml:"path"`
	Content     string `yaml:"content,omitempty"`
	Owner       string `yaml:"owner,omitempty"`
	Permissions string `yaml:"permissions,omitempty"`
	Encoding    string `yaml:"encoding,omitempty"`
	Append      string `yaml:"append,omitempty"`
}

const cloudInitHeader = "#cloud-config\n"

func (config *CloudConfig) Generate() (string, error) {
	var buf bytes.Buffer
	if _, err := buf.WriteString(cloudInitHeader); err != nil {
		return "", fmt.Errorf("unable to write header, cause: %w", err)
	}
	enc := yaml.NewEncoder(&buf)
	if err := enc.Encode(config); err != nil {
		return "", fmt.Errorf("unable to encode config, cause: %w", err)
	}
	if err := enc.Close(); err != nil {
		return "", fmt.Errorf("unable to close encoder, cause: %w", err)
	}
	return buf.String(), nil
}

func AuthJSONToResourcesJSON(text string) string {
	var buf bytes.Buffer
	tpl := template.Must(template.New("cerdTpl").Parse("{\"default/credential/test\":\"{{.EncodedAuth}}\"}"))
	if err := tpl.Execute(&buf, struct{ EncodedAuth string }{base64.StdEncoding.EncodeToString([]byte(text))}); err != nil {
		return ""
	}
	return buf.String()
}

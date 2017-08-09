// +build linux !darwin

package common

// SetNfaType -- Sets Netfilter attribute type
func (r *NfAttr) SetNfaType(t uint16) {
	r.nfaType = t
}

// SetNfaLen -- Sets Netfilter attribute length
func (r *NfAttr) SetNfaLen(l uint16) {
	r.nfaLen = l
}

// Set8Value -- Sets value for uint8 type
func (r *NfValue8) Set8Value(v uint8) {
	r.value = v
}

// Set16Value -- Sets value for uint16 type
func (r *NfValue16) Set16Value(v uint16) {
	r.value = v
}

// SetNetlinkData -- Sets netlink data
func SetNetlinkData(b uint32) *NfAttrResponsePayload {
	return &NfAttrResponsePayload{
		data: make([]byte, b),
	}
}

// Set32Value -- Sets value for uint32 type
func (r *NfValue32) Set32Value(v uint32) {
	r.value = v
}

// GetNfaType -- Get Netfilter attribute type
func (r *NfAttr) GetNfaType() uint16 {
	return r.nfaType
}

// GetNfaLen -- Get Netfilter attribute length
func (r *NfAttr) GetNfaLen() uint16 {
	return r.nfaLen
}

// Get8Value -- Get value for uint8 type
func (r *NfValue8) Get8Value() uint8 {
	return r.value
}

// Get16Value -- Get value for uint16 type
func (r *NfValue16) Get16Value() uint16 {
	return r.value
}

// Get32Value -- Get value for uint32 type
func (r *NfValue32) Get32Value() uint32 {
	return r.value
}

// GetNetlinkData -- Get netlink data
func (d *NfAttrResponsePayload) GetNetlinkData() []byte {
	return d.data
}

// GetNetlinkDataArray -- Get netlink data from array
func GetNetlinkDataArray(index int, d []*NfAttrResponsePayload) []byte {
	return d[index].data
}

// GetNfgenFamily -- Get  Nfgen family
func (nfg *NfqGenMsg) GetNfgenFamily() uint8 {
	return nfg.nfgenFamily
}

// GetNfgenFamily -- Get  Nfgen version
func (nfg *NfqGenMsg) GetNfgenVersion() uint8 {
	return nfg.version
}

// GetNfgenResID -- Get Nfgen res
func (nfg *NfqGenMsg) GetNfgenResID() uint16 {
	return nfg.resID
}

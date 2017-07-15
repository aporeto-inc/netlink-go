package commons

func (r *NfAttr) SetNfaType(t uint16) {
	r.nfaType = t
}

func (r *NfAttr) SetNfaLen(l uint16) {
	r.nfaLen = l
}

func (r *NfValue8) Set8Value(v uint8) {
	r.value = v
}

func (r *NfValue16) Set16Value(v uint16) {
	r.value = v
}

func SetNetlinkData(b uint32) *NfAttrResponsePayload {
	return &NfAttrResponsePayload{
		data: make([]byte, b),
	}
}

func (r *NfValue32) Set32Value(v uint32) {
	r.value = v
}

func (r *NfAttr) GetNfaType() uint16 {
	return r.nfaType
}

func (r *NfAttr) GetNfaLen() uint16 {
	return r.nfaLen
}

func (r *NfValue8) Get8Value() uint8 {
	return r.value
}

func (r *NfValue16) Get16Value() uint16 {
	return r.value
}

func (r *NfValue32) Get32Value() uint32 {
	return r.value
}

func (d *NfAttrResponsePayload) GetNetlinkData() []byte {
	return d.data
}

func GetNetlinkDataArray(index int, d []*NfAttrResponsePayload) []byte {
	return d[index].data
}

func (nfg *NfqGenMsg) GetNfgenFamily() uint8 {
	return nfg.nfgenFamily
}

func (nfg *NfqGenMsg) GetNfgenVersion() uint8 {
	return nfg.version
}

func (nfg *NfqGenMsg) GetNfgenResID() uint16 {
	return nfg.resID
}

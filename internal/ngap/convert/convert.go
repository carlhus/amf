package convert

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/free5gc/ngap/aper"
	"github.com/free5gc/ngap/ie"
	"github.com/free5gc/openapi/models"
)

func BitStringToHex(value *aper.BitString) string {
	if value == nil {
		return ""
	}
	encoded := hex.EncodeToString(value.Bytes)
	length := int((value.BitLength + 3) / 4)
	if length > len(encoded) {
		return encoded
	}
	return encoded[:length]
}

func HexToBitString(value string, bitLength int) aper.BitString {
	if len(value) != (bitLength+3)/4 {
		return aper.BitString{}
	}
	if len(value)%2 != 0 {
		value += "0"
	}
	bytes, err := hex.DecodeString(value)
	if err != nil {
		return aper.BitString{}
	}
	result := aper.BitString{Bytes: bytes, BitLength: uint64(bitLength)}
	if remainder := bitLength % 8; remainder != 0 && len(result.Bytes) != 0 {
		result.Bytes[len(result.Bytes)-1] &= byte(0xff << (8 - remainder))
	}
	return result
}

func ByteToBitString(value []byte, bitLength int) aper.BitString {
	if (bitLength+7)/8 > len(value) {
		return aper.BitString{}
	}
	return aper.BitString{Bytes: value, BitLength: uint64(bitLength)}
}

func PlmnIdToModels(value ie.PLMNIdentity) models.PlmnId {
	encoded := hex.EncodeToString(value.Value)
	if len(encoded) != 6 {
		return models.PlmnId{}
	}
	nibbles := strings.Split(encoded, "")
	result := models.PlmnId{Mcc: nibbles[1] + nibbles[0] + nibbles[3]}
	if nibbles[2] == "f" {
		result.Mnc = nibbles[5] + nibbles[4]
	} else {
		result.Mnc = nibbles[2] + nibbles[5] + nibbles[4]
	}
	return result
}

func PlmnIdToNgap(value models.PlmnId) ie.PLMNIdentity {
	if len(value.Mcc) != 3 || (len(value.Mnc) != 2 && len(value.Mnc) != 3) {
		return ie.PLMNIdentity{}
	}
	mcc := strings.Split(value.Mcc, "")
	mnc := strings.Split(value.Mnc, "")
	encoded := mcc[1] + mcc[0]
	if len(mnc) == 2 {
		encoded += "f" + mcc[2] + mnc[1] + mnc[0]
	} else {
		encoded += mnc[0] + mcc[2] + mnc[2] + mnc[1]
	}
	bytes, err := hex.DecodeString(encoded)
	if err != nil {
		return ie.PLMNIdentity{}
	}
	return ie.PLMNIdentity{Value: bytes}
}

func SNssaiToModels(value ie.SNSSAI) models.Snssai {
	result := models.Snssai{}
	if value.SST != nil && len(value.SST.Value) != 0 {
		result.Sst = int32(value.SST.Value[0])
	}
	if value.SD != nil {
		result.Sd = hex.EncodeToString(value.SD.Value)
	}
	return result
}

func SNssaiToNgap(value models.Snssai) ie.SNSSAI {
	result := ie.SNSSAI{SST: &ie.SST{Value: []byte{byte(value.Sst)}}}
	if value.Sd != "" {
		if sd, err := hex.DecodeString(value.Sd); err == nil {
			result.SD = &ie.SD{Value: sd}
		}
	}
	return result
}

func AllowedNssaiToNgap(values []models.Nssf_NSSel_AllowedSnssai) ie.AllowedNSSAI {
	result := ie.AllowedNSSAI{}
	for _, value := range values {
		if value.AllowedSnssai == nil {
			continue
		}
		snssai := SNssaiToNgap(*value.AllowedSnssai)
		result.List = append(result.List, ie.AllowedNSSAIItem{SNSSAI: &snssai})
	}
	return result
}

func TaiToModels(value ie.TAI) models.Tai {
	result := models.Tai{}
	if value.PLMNIdentity != nil {
		plmn := PlmnIdToModels(*value.PLMNIdentity)
		result.PlmnId = &plmn
	}
	if value.TAC != nil {
		result.Tac = hex.EncodeToString(value.TAC.Value)
	}
	return result
}

func IPAddressToString(value ie.TransportLayerAddress) (string, string) {
	switch value.Value.BitLength {
	case 32:
		return net.IP(value.Value.Bytes).String(), ""
	case 128:
		return "", net.IP(value.Value.Bytes).String()
	case 160:
		return net.IP(value.Value.Bytes[:4]).String(), net.IP(value.Value.Bytes[4:]).String()
	default:
		return "", ""
	}
}

func IPAddressToNgap(ipv4, ipv6 string) ie.TransportLayerAddress {
	var bytes []byte
	switch {
	case ipv4 != "" && ipv6 != "":
		bytes = append(bytes, net.ParseIP(ipv4).To4()...)
		bytes = append(bytes, net.ParseIP(ipv6).To16()...)
	case ipv4 != "":
		bytes = append(bytes, net.ParseIP(ipv4).To4()...)
	case ipv6 != "":
		bytes = append(bytes, net.ParseIP(ipv6).To16()...)
	}
	return ie.TransportLayerAddress{
		Value: aper.BitString{Bytes: bytes, BitLength: uint64(len(bytes) * 8)},
	}
}

func AmfIdToNgap(amfID string) (aper.BitString, aper.BitString, aper.BitString) {
	if len(amfID) != 6 {
		return aper.BitString{}, aper.BitString{}, aper.BitString{}
	}
	region := HexToBitString(amfID[:2], 8)
	set := HexToBitString(amfID[2:5], 10)
	last, err := hex.DecodeString(amfID[4:])
	if err != nil || len(last) != 1 {
		return region, set, aper.BitString{}
	}
	pointer := aper.BitString{Bytes: []byte{last[0] << 2}, BitLength: 6}
	return region, set, pointer
}

func AmfIdToModels(region, set, pointer aper.BitString) string {
	if len(set.Bytes) < 2 || len(pointer.Bytes) < 1 {
		return ""
	}
	return BitStringToHex(&region) +
		hex.EncodeToString([]byte{set.Bytes[0], (set.Bytes[1] & 0xc0) | (pointer.Bytes[0] >> 2)})
}

func UEAmbrToInt64(value string) int64 {
	parts := strings.Fields(value)
	if len(parts) != 2 {
		return 0
	}
	number, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0
	}
	units := map[string]float64{
		"bps": 1, "Kbps": 1e3, "Mbps": 1e6, "Gbps": 1e9, "Tbps": 1e12,
	}
	return int64(number * units[parts[1]])
}

func RATRestrictionInformationToNgap(value models.RatType) ie.RATRestrictionInformation {
	result := ie.RATRestrictionInformation{Value: aper.BitString{BitLength: 8}}
	switch value {
	case models.RatType_EUTRA:
		result.Value.Bytes = []byte{0x80}
	case models.RatType_NR:
		result.Value.Bytes = []byte{0x40}
	}
	return result
}

// SupportedTAItemRatType returns the RatType a Supported TA declares through its
// RAT Information extension, or "" when it declares none.
func SupportedTAItemRatType(item ie.SupportedTAItem) models.RatType {
	if item.IEExtensions == nil {
		return ""
	}
	for _, extension := range item.IEExtensions.List {
		if extension.RATInformation == nil {
			continue
		}
		switch extension.RATInformation.Value {
		case ie.RATInformationPresentNRLEO:
			return models.RatType_NR_LEO
		case ie.RATInformationPresentNRMEO:
			return models.RatType_NR_MEO
		case ie.RATInformationPresentNRGEO:
			return models.RatType_NR_GEO
		case ie.RATInformationPresentNROTHERSAT:
			return models.RatType_NR_OTHER_SAT
		}
	}
	return ""
}

func RanIdToModels(value ie.GlobalRANNodeID) models.GlobalRanNodeId {
	result := models.GlobalRanNodeId{}
	switch choice := value.Choice.(type) {
	case *ie.GlobalGNBID:
		if choice.PLMNIdentity != nil {
			plmn := PlmnIdToModels(*choice.PLMNIdentity)
			result.PlmnId = &plmn
		}
		if choice.GNBID != nil {
			if id, ok := choice.GNBID.Choice.(*ie.GNBIDForGNBID); ok {
				result.GNbId = &models.GNbId{
					BitLength: int32(id.Value.BitLength),
					GNBValue:  BitStringToHex(&id.Value),
				}
			}
		}
	case *ie.GlobalNgENBID:
		if choice.PLMNIdentity != nil {
			plmn := PlmnIdToModels(*choice.PLMNIdentity)
			result.PlmnId = &plmn
		}
		if choice.NgENBID != nil {
			switch id := choice.NgENBID.Choice.(type) {
			case *ie.MacroNgENBIDForNgENBID:
				result.NgeNbId = "MacroNGeNB-" + BitStringToHex(&id.Value)
			case *ie.ShortMacroNgENBIDForNgENBID:
				result.NgeNbId = "SMacroNGeNB-" + BitStringToHex(&id.Value)
			case *ie.LongMacroNgENBIDForNgENBID:
				result.NgeNbId = "LMacroNGeNB-" + BitStringToHex(&id.Value)
			}
		}
	case *ie.GlobalN3IWFID:
		if choice.PLMNIdentity != nil {
			plmn := PlmnIdToModels(*choice.PLMNIdentity)
			result.PlmnId = &plmn
		}
		if choice.N3IWFID != nil {
			if id, ok := choice.N3IWFID.Choice.(*ie.N3IWFIDForN3IWFID); ok {
				result.N3IwfId = BitStringToHex(&id.Value)
			}
		}
	}
	return result
}

func RanIDToNgap(value models.GlobalRanNodeId) (ie.GlobalRANNodeID, error) {
	plmn := PlmnIdToNgap(*value.PlmnId)
	switch {
	case value.GNbId != nil:
		return ie.GlobalRANNodeID{Choice: &ie.GlobalGNBID{
			PLMNIdentity: &plmn,
			GNBID: &ie.GNBID{Choice: &ie.GNBIDForGNBID{
				Value: HexToBitString(value.GNbId.GNBValue, int(value.GNbId.BitLength)),
			}},
		}}, nil
	case value.NgeNbId != "":
		var choice ie.NgENBIDAlt
		switch {
		case strings.HasPrefix(value.NgeNbId, "MacroNGeNB-"):
			choice = &ie.MacroNgENBIDForNgENBID{Value: HexToBitString(strings.TrimPrefix(value.NgeNbId, "MacroNGeNB-"), 20)}
		case strings.HasPrefix(value.NgeNbId, "SMacroNGeNB-"):
			choice = &ie.ShortMacroNgENBIDForNgENBID{
				Value: HexToBitString(strings.TrimPrefix(value.NgeNbId, "SMacroNGeNB-"), 18),
			}
		case strings.HasPrefix(value.NgeNbId, "LMacroNGeNB-"):
			choice = &ie.LongMacroNgENBIDForNgENBID{Value: HexToBitString(strings.TrimPrefix(value.NgeNbId, "LMacroNGeNB-"), 21)}
		default:
			return ie.GlobalRANNodeID{}, fmt.Errorf("unsupported ng-eNB ID %q", value.NgeNbId)
		}
		return ie.GlobalRANNodeID{Choice: &ie.GlobalNgENBID{
			PLMNIdentity: &plmn,
			NgENBID:      &ie.NgENBID{Choice: choice},
		}}, nil
	case value.N3IwfId != "":
		return ie.GlobalRANNodeID{Choice: &ie.GlobalN3IWFID{
			PLMNIdentity: &plmn,
			N3IWFID: &ie.N3IWFID{Choice: &ie.N3IWFIDForN3IWFID{
				Value: HexToBitString(value.N3IwfId, len(value.N3IwfId)*4),
			}},
		}}, nil
	default:
		return ie.GlobalRANNodeID{}, fmt.Errorf("global RAN node ID is empty")
	}
}

func TraceDataToNgap(value models.TraceData, sessionReference string) ie.TraceActivation {
	result := ie.TraceActivation{}
	parts := strings.Split(value.TraceRef, "-")
	if len(parts) != 2 || len(sessionReference) != 4 || len(parts[0]) < 5 {
		return result
	}
	plmn := PlmnIdToNgap(models.PlmnId{Mcc: parts[0][:3], Mnc: parts[0][3:]})
	traceID, err := hex.DecodeString(parts[1] + sessionReference)
	if err != nil {
		return result
	}
	result.NGRANTraceID = &ie.NGRANTraceID{Value: append(plmn.Value, traceID...)}
	if interfaces, interfaceErr := hex.DecodeString(value.InterfaceList); interfaceErr == nil {
		result.InterfacesToTrace = &ie.InterfacesToTrace{
			Value: aper.BitString{Bytes: interfaces, BitLength: 8},
		}
	}
	depth := map[models.TraceDepth]aper.Enumerated{
		models.TraceDepth_MINIMUM:                     ie.TraceDepthPresentMinimum,
		models.TraceDepth_MEDIUM:                      ie.TraceDepthPresentMedium,
		models.TraceDepth_MAXIMUM:                     ie.TraceDepthPresentMaximum,
		models.TraceDepth_MINIMUM_WO_VENDOR_EXTENSION: ie.TraceDepthPresentMinimumWithoutVendorSpecificExtension,
		models.TraceDepth_MEDIUM_WO_VENDOR_EXTENSION:  ie.TraceDepthPresentMediumWithoutVendorSpecificExtension,
		models.TraceDepth_MAXIMUM_WO_VENDOR_EXTENSION: ie.TraceDepthPresentMaximumWithoutVendorSpecificExtension,
	}
	result.TraceDepth = &ie.TraceDepth{Value: depth[value.TraceDepth]}
	address := IPAddressToNgap(value.CollectionEntityIpv4Addr, value.CollectionEntityIpv6Addr)
	result.TraceCollectionEntityIPAddress = &address
	return result
}

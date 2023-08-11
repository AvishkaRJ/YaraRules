import "pe"
import "console"

rule clip64_Strings{
    meta:
        Author="AJ"
        rulenum="001"
        filetype="dll"
        hash="c859fc5f8152939cd66236aebebde905457ca017e02c0e0c7c706d13e94fa7ec"
        ref="https://bazaar.abuse.ch/sample/c859fc5f8152939cd66236aebebde905457ca017e02c0e0c7c706d13e94fa7ec/"
    strings:
        $a1="D:\\Mktmp\\Amadey\\ClipperDLL\\Release\\CLIPPERDLL.pdb"
        $b01=".CRT$XCA"
        $b02=".CRT$XCU"
        $b03=".CRT$XCZ"
        $b04=".CRT$XIA"
        $b05=".CRT$XIC"
        $b06=".CRT$XIZ"
        $b07=".CRT$XPA"
        $b08=".CRT$XPX"
        $b09=".CRT$XPXA"
        $b10=".CRT$XPZ"
        $b11=".CRT$XTA"
        $b12=".CRT$XTZ"
    condition:
        uint16be(0)==0x4d5a and
        //console.hex("Value is ",uint16be(0)) and
        $a1 and 5 of ($b*)

}

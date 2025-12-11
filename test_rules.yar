rule Test_EICAR_String
{
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

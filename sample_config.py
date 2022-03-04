
session_config = {
    "session_backing":{
        "cache_type": "FileSystem", 
        "cache_dir": "./.cache"
    },
    "session_expire" : 7200,
    "session_cookie" :"cascookie"
}

saml_config = {
    "saml_endpoint": "https://login.microsoftonline.com/<TENENT-ID>/saml2",
    "spid": "URN:test1",
    "issuer": "https://sts.windows.net/<TENENT-ID>/",
    "acs_url" : "https://cas.example.com/saml/acs",
    "force_reauth" : False,
    "user_attr": "uid",
    "assertions": [
        "uid", "givenname", "surname", "upn", "emailaddress", "groups"],
    "certificate" : "-----BEGIN CERTIFICATE-----\nMIIC8DC ...T1EaBUpGQQoZwfjd\nINOMeQRn+fXDb9P+1k/S\n-----END CERTIFICATE-----\n"
}

cas_config = {
    "cas_st_life" : 500,
    "cas_ticket_granting_ticket_life" : 28800, 
    "cas_services_filename" : None,
    "info_page" : True
}

from dateutil.parser import parse as parse_date

prog_not_vuln = {"program_name" : "firefox", "program_version" : "1337", "minimum_score": 0,"poste": "changed"}
prog_vuln = {"program_name" : "bzip2", "program_version" : "1.0.6", "minimum_score": 1,"poste": "changed"}
prog_vuln2 = {"program_name" : "glibc", "program_version" : "2.23", "minimum_score": 1,"poste": "changed"}
prog_vuln_multi = [prog_vuln, prog_vuln2]

prog_vuln_before_update = {"program_name" : "bzip2", "program_version" : "1.0.5", "minimum_score": 0,"poste": "changed"}

proglist_vuln = {"programs_list": [prog_vuln], "poste": "changed"}
proglist_vuln_multi = {"programs_list": prog_vuln_multi, "poste": "changed"}
proglist_vuln_before_update = {"programs_list": [prog_vuln_before_update], "poste": "changed"}

cpes = [
    {"cpe": "bzip2:1.0.6", "product": "bzip2", "version": "1.0.6"},
    {"cpe": "glibc:2.23", "product": "glibc", "version": "2.23"}
]
cves = [
    {"cveid": "CVE-2016-3189",
     "published_date": parse_date("2016-06-30T13:59:01.470-04:00"),
     "modified_date": parse_date("2016-07-01T18:22:05.107-04:00"),
     "cvss_score": 4.3,
     "summary": "Use-after-free vulnerability in bzip2recover in bzip2 1.0.6 allows remote attackers to cause a denial of service (crash) via a crafted bzip2 file, related to block ends set to before the start of the block."
    },
    {"cveid": "CVE-2016-3075",
     "published_date": parse_date("2016-06-01T16:59:03.043-04:00"),
     "modified_date": parse_date("2016-06-16T10:54:31.857-04:00"),
     "cvss_score": 5,
     "summary": "Stack-based buffer overflow in the nss_dns implementation of the getnetbyname function in GNU C Library (aka glibc) before 2.24 allows context-dependent attackers to cause a denial of service (stack consumption and application crash) via a long name."
    }
]

cve_cpe = {
    "CVE-2016-3189": ["bzip2:1.0.6"],
    "CVE-2016-3075": ["glibc:2.23"]
}

scanner = {"name": "Test station"}

set_alert_as_new = {"new" : True}
set_alert_as_old = {"new" : False}

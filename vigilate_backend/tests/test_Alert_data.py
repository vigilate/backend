from dateutil.parser import parse as parse_date

prog_not_vuln = {"program_name" : "firefox", "program_version" : "1337", "minimum_score": 0,"poste": 1}
prog_vuln = {"program_name" : "bzip2", "program_version" : "1.0.6", "minimum_score": 1,"poste": 1}

prog_vuln_before_update = {"program_name" : "bzip2", "program_version" : "1.0.5", "minimum_score": 0,"poste": 1}

proglist_vuln = {"programs_list": [prog_vuln], "poste": 1}
proglist_vuln_before_update = {"programs_list": [prog_vuln_before_update], "poste": 1}

cpe = {"cpe": "bzip2:1.0.6", "product": "bzip2", "version": "1.0.6"}
cve = {"cveid": "2016-3189",
       "published_date": parse_date("2016-06-30T13:59:01.470-04:00"),
       "modified_date": parse_date("2016-07-01T18:22:05.107-04:00"),
       "cvss_score": 4.3,
       "summary": "Use-after-free vulnerability in bzip2recover in bzip2 1.0.6 allows remote attackers to cause a denial of service (crash) via a crafted bzip2 file, related to block ends set to before the start of the block."
}
cve_cpe = ["bzip2:1.0.6"]

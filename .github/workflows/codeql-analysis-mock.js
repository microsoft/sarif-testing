const { readFileSync, writeFileSync } = require('fs')

const lines = readFileSync('src/VulnerableWebService/Controllers/DatastoreController.cs', 'utf8').split('\n')

const results = [
    // Line 14: cs/path-injection
    {
        "codeFlows": [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    "message": {
                                        "text": "path : String"
                                    },
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "index": 0,
                                            "uri": "src/VulnerableWebService/Controllers/DatastoreController.cs"
                                        },
                                        "region": {
                                            "endColumn": 50,
                                            "endLine": 12,
                                            "startColumn": 46,
                                            "startLine": 12
                                        }
                                    }
                                }
                            },
                            {
                                "location": {
                                    "message": {
                                        "text": "access to parameter path"
                                    },
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "index": 0,
                                            "uri": "src/VulnerableWebService/Controllers/DatastoreController.cs"
                                        },
                                        "region": {
                                            "endColumn": 51,
                                            "endLine": 14,
                                            "startColumn": 47,
                                            "startLine": 14
                                        }
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        ],
        "correlationGuid": "c895223c-c536-496d-9794-a843a64a5bd7",
        "level": "error",
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "index": 0,
                        "uri": "src/VulnerableWebService/Controllers/DatastoreController.cs"
                    },
                    "region": {
                        "endColumn": 51,
                        "endLine": 14,
                        "startColumn": 47,
                        "startLine": 14
                    }
                }
            }
        ],
        "message": {
            "text": "[User-provided value](1) flows to here and is used in a path."
        },
        "partialFingerprints": {
            "primaryLocationLineHash": "4563c7ab93f38773:1"
        },
        "properties": {
            "github/alertNumber": 75,
            "github/alertUrl": "https://api.github.com/repos/microsoft/sarif-testing/code-scanning/alerts/75"
        },
        "relatedLocations": [
            {
                "id": 1,
                "message": {
                    "text": "User-provided value"
                },
                "physicalLocation": {
                    "artifactLocation": {
                        "index": 0,
                        "uri": "src/VulnerableWebService/Controllers/DatastoreController.cs"
                    },
                    "region": {
                        "endColumn": 50,
                        "endLine": 12,
                        "startColumn": 46,
                        "startLine": 12
                    }
                }
            }
        ],
        "rule": {
            "id": "cs/path-injection",
            "toolComponent": {
                "index": 0
            },
            "index": 1
        },
        "ruleId": "cs/path-injection"
    },
    // Line 20: cs/regex-injection
    {
        "artifactChanges": [
            {
                "artifactLocation": {
                    "uri": "src/VulnerableWebService/Controllers/DatastoreController.cs"
                },
                "replacements": [
                    {
                        "deletedRegion": {
                            "endColumn": 45,
                            "endLine": 20,
                            "startColumn": 45,
                            "startLine": 20
                        },
                        "insertedContent": {
                            "text": "Regex.escape("
                        }
                    },
                    {
                        "deletedRegion": {
                            "endColumn": 61,
                            "endLine": 20,
                            "startColumn": 61,
                            "startLine": 20
                        },
                        "insertedContent": {
                            "text": ")"
                        }
                    }
                ]
            }
        ],
        "codeFlows": [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    "message": {
                                        "text": "token : String"
                                    },
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "index": 0,
                                            "uri": "src/VulnerableWebService/Controllers/DatastoreController.cs"
                                        },
                                        "region": {
                                            "endColumn": 48,
                                            "endLine": 17,
                                            "startColumn": 43,
                                            "startLine": 17
                                        }
                                    }
                                }
                            },
                            {
                                "location": {
                                    "message": {
                                        "text": "... + ..."
                                    },
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "index": 0,
                                            "uri": "src/VulnerableWebService/Controllers/DatastoreController.cs"
                                        },
                                        "region": {
                                            "endColumn": 61,
                                            "endLine": 20,
                                            "startColumn": 45,
                                            "startLine": 20
                                        }
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        ],
        "correlationGuid": "43521ed1-0647-408b-8d37-c35931c887b0",
        "level": "error",
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "index": 0,
                        "uri": "src/VulnerableWebService/Controllers/DatastoreController.cs"
                    },
                    "region": {
                        "endColumn": 61,
                        "endLine": 20,
                        "startColumn": 45,
                        "startLine": 20
                    }
                }
            }
        ],
        "message": {
            "text": "[User-provided value](1) flows to the construction of a regular expression."
        },
        "partialFingerprints": {
            "primaryLocationLineHash": "8644a2c433a94b22:1"
        },
        "properties": {
            "github/alertNumber": 76,
            "github/alertUrl": "https://api.github.com/repos/microsoft/sarif-testing/code-scanning/alerts/76"
        },
        "relatedLocations": [
            {
                "id": 1,
                "message": {
                    "text": "User-provided value"
                },
                "physicalLocation": {
                    "artifactLocation": {
                        "index": 0,
                        "uri": "src/VulnerableWebService/Controllers/DatastoreController.cs"
                    },
                    "region": {
                        "endColumn": 48,
                        "endLine": 17,
                        "startColumn": 43,
                        "startLine": 17
                    }
                }
            }
        ],
        "rule": {
            "id": "cs/regex-injection",
            "toolComponent": {
                "index": 0
            },
            "index": 2
        },
        "ruleId": "cs/regex-injection"
    },
    // Line 29: cs/insecure-sql-connection
    {
        "correlationGuid": "9fddcd95-eb30-4927-999b-b0fbca526ba8",
        "level": "error",
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "index": 0,
                        "uri": "src/VulnerableWebService/Controllers/DatastoreController.cs"
                    },
                    "region": {
                        "endColumn": 70,
                        "endLine": 29,
                        "startColumn": 48,
                        "startLine": 29
                    }
                }
            }
        ],
        "message": {
            "text": "[Connection string](1) flows to here and does not specify `Encrypt=True`."
        },
        "partialFingerprints": {
            "primaryLocationLineHash": "d3921fecc4af276:1"
        },
        "properties": {
            "github/alertNumber": 74,
            "github/alertUrl": "https://api.github.com/repos/microsoft/sarif-testing/code-scanning/alerts/74"
        },
        "relatedLocations": [
            {
                "id": 1,
                "message": {
                    "text": "Connection string"
                },
                "physicalLocation": {
                    "artifactLocation": {
                        "index": 0,
                        "uri": "src/VulnerableWebService/Controllers/DatastoreController.cs"
                    },
                    "region": {
                        "endColumn": 70,
                        "endLine": 29,
                        "startColumn": 48,
                        "startLine": 29
                    }
                }
            }
        ],
        "rule": {
            "id": "cs/insecure-sql-connection",
            "toolComponent": {
                "index": 0
            },
            "index": 0
        },
        "ruleId": "cs/insecure-sql-connection"
    },
    // Line 31: cs/sql-injection
    {
        "codeFlows": [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    "message": {
                                        "text": "id : String"
                                    },
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "index": 0,
                                            "uri": "src/VulnerableWebService/Controllers/DatastoreController.cs"
                                        },
                                        "region": {
                                            "endColumn": 43,
                                            "endLine": 25,
                                            "startColumn": 41,
                                            "startLine": 25
                                        }
                                    }
                                }
                            },
                            {
                                "location": {
                                    "message": {
                                        "text": "access to local variable sql"
                                    },
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "index": 0,
                                            "uri": "src/VulnerableWebService/Controllers/DatastoreController.cs"
                                        },
                                        "region": {
                                            "endColumn": 34,
                                            "endLine": 31,
                                            "startColumn": 31,
                                            "startLine": 31
                                        }
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        ],
        "correlationGuid": "46bff074-af74-4aac-9cc5-e646fced8216",
        "level": "error",
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "index": 0,
                        "uri": "src/VulnerableWebService/Controllers/DatastoreController.cs"
                    },
                    "region": {
                        "endColumn": 34,
                        "endLine": 31,
                        "startColumn": 31,
                        "startLine": 31
                    }
                }
            }
        ],
        "message": {
            "text": "Query might include code from [this ASP.NET Core MVC action method parameter](1)."
        },
        "partialFingerprints": {
            "primaryLocationLineHash": "53a937a13278ace8:1"
        },
        "properties": {
            "github/alertNumber": 73,
            "github/alertUrl": "https://api.github.com/repos/microsoft/sarif-testing/code-scanning/alerts/73"
        },
        "relatedLocations": [
            {
                "id": 1,
                "message": {
                    "text": "this ASP.NET Core MVC action method parameter"
                },
                "physicalLocation": {
                    "artifactLocation": {
                        "index": 0,
                        "uri": "src/VulnerableWebService/Controllers/DatastoreController.cs"
                    },
                    "region": {
                        "endColumn": 43,
                        "endLine": 25,
                        "startColumn": 41,
                        "startLine": 25
                    }
                }
            }
        ],
        "rule": {
            "id": "cs/sql-injection",
            "toolComponent": {
                "index": 0
            },
            "index": 3
        },
        "ruleId": "cs/sql-injection"
    }
]

const log = {
	"runs": [
		{
			"artifacts": [
				{
					"location": {
						"index": 0,
						"uri": "src/VulnerableWebService/Controllers/DatastoreController.cs"
					}
				}
			],
			"automationDetails": {
				"id": ".github/workflows/codeql-analysis.yml:analyze/"
			},
			"conversion": {
				"tool": {
					"driver": {
						"name": "GitHub Code Scanning"
					}
				}
			},
			"results": [],
			"tool": {
				"driver": {
					"name": "CodeQL",
					"semanticVersion": "2.10.3"
				},
				"extensions": [
					{
						"name": "codeql/csharp-queries",
						"rules": [
							{
								"defaultConfiguration": {
									"level": "error"
								},
								"fullDescription": {
									"text": "Using an SQL Server connection without enforcing encryption is a security vulnerability."
								},
								"help": {
									"markdown": "# Insecure SQL connection\nSQL Server connections where the client is not enforcing the encryption in transit are susceptible to multiple attacks, including a man-in-the-middle, that would potentially compromise the user credentials and/or the TDS session.\n\n\n## Recommendation\nEnsure that the client code enforces the `Encrypt` option by setting it to `true` in the connection string.\n\n\n## Example\nThe following example shows a SQL connection string that is not explicitly enabling the `Encrypt` setting to force encryption.\n\n\n```csharp\nusing System.Data.SqlClient;\n\n// BAD, Encrypt not specified\nstring connectString =\n    \"Server=1.2.3.4;Database=Anything;Integrated Security=true;\";\nSqlConnectionStringBuilder builder = new SqlConnectionStringBuilder(connectString);\nvar conn = new SqlConnection(builder.ConnectionString);\n```\nThe following example shows a SQL connection string that is explicitly enabling the `Encrypt` setting to force encryption in transit.\n\n\n```csharp\nusing System.Data.SqlClient;\n\nstring connectString =\n    \"Server=1.2.3.4;Database=Anything;Integrated Security=true;;Encrypt=true;\";\nSqlConnectionStringBuilder builder = new SqlConnectionStringBuilder(connectString);\nvar conn = new SqlConnection(builder.ConnectionString);\n```\n\n## References\n* Microsoft, SQL Protocols blog: [Selectively using secure connection to SQL Server](https://blogs.msdn.microsoft.com/sql_protocols/2009/10/19/selectively-using-secure-connection-to-sql-server/).\n* Microsoft: [SqlConnection.ConnectionString Property](https://msdn.microsoft.com/en-us/library/system.data.sqlclient.sqlconnection.connectionstring(v=vs.110).aspx).\n* Microsoft: [Using Connection String Keywords with SQL Server Native Client](https://msdn.microsoft.com/en-us/library/ms130822.aspx).\n* Microsoft: [Setting the connection properties](https://msdn.microsoft.com/en-us/library/ms378988(v=sql.110).aspx).\n* Common Weakness Enumeration: [CWE-327](https://cwe.mitre.org/data/definitions/327.html).\n",
									"text": "# Insecure SQL connection\nSQL Server connections where the client is not enforcing the encryption in transit are susceptible to multiple attacks, including a man-in-the-middle, that would potentially compromise the user credentials and/or the TDS session.\n\n\n## Recommendation\nEnsure that the client code enforces the `Encrypt` option by setting it to `true` in the connection string.\n\n\n## Example\nThe following example shows a SQL connection string that is not explicitly enabling the `Encrypt` setting to force encryption.\n\n\n```csharp\nusing System.Data.SqlClient;\n\n// BAD, Encrypt not specified\nstring connectString =\n    \"Server=1.2.3.4;Database=Anything;Integrated Security=true;\";\nSqlConnectionStringBuilder builder = new SqlConnectionStringBuilder(connectString);\nvar conn = new SqlConnection(builder.ConnectionString);\n```\nThe following example shows a SQL connection string that is explicitly enabling the `Encrypt` setting to force encryption in transit.\n\n\n```csharp\nusing System.Data.SqlClient;\n\nstring connectString =\n    \"Server=1.2.3.4;Database=Anything;Integrated Security=true;;Encrypt=true;\";\nSqlConnectionStringBuilder builder = new SqlConnectionStringBuilder(connectString);\nvar conn = new SqlConnection(builder.ConnectionString);\n```\n\n## References\n* Microsoft, SQL Protocols blog: [Selectively using secure connection to SQL Server](https://blogs.msdn.microsoft.com/sql_protocols/2009/10/19/selectively-using-secure-connection-to-sql-server/).\n* Microsoft: [SqlConnection.ConnectionString Property](https://msdn.microsoft.com/en-us/library/system.data.sqlclient.sqlconnection.connectionstring(v=vs.110).aspx).\n* Microsoft: [Using Connection String Keywords with SQL Server Native Client](https://msdn.microsoft.com/en-us/library/ms130822.aspx).\n* Microsoft: [Setting the connection properties](https://msdn.microsoft.com/en-us/library/ms378988(v=sql.110).aspx).\n* Common Weakness Enumeration: [CWE-327](https://cwe.mitre.org/data/definitions/327.html).\n"
								},
								"id": "cs/insecure-sql-connection",
								"name": "cs/insecure-sql-connection",
								"properties": {
									"precision": "medium",
									"queryURI": "https://github.com/github/codeql/blob/f30b735443ec9f7528b51628a16510dce4ea0a56/csharp/ql/src/Security%20Features/CWE-327/InsecureSQLConnection.ql",
									"security-severity": "7.500000",
									"tags": [
										"external/cwe/cwe-327",
										"security"
									]
								},
								"shortDescription": {
									"text": "Insecure SQL connection"
								}
							},
							{
								"defaultConfiguration": {
									"level": "error"
								},
								"fullDescription": {
									"text": "Accessing paths influenced by users can allow an attacker to access unexpected resources."
								},
								"help": {
									"markdown": "# Uncontrolled data used in path expression\nAccessing paths controlled by users can allow an attacker to access unexpected resources. This can result in sensitive information being revealed or deleted, or an attacker being able to influence behavior by modifying unexpected files.\n\nPaths that are naively constructed from data controlled by a user may contain unexpected special characters, such as \"..\". Such a path may potentially point to any directory on the file system.\n\n\n## Recommendation\nValidate user input before using it to construct a file path. Ideally, follow these rules:\n\n* Do not allow more than a single \".\" character.\n* Do not allow directory separators such as \"/\" or \"\\\\\" (depending on the file system).\n* Do not rely on simply replacing problematic sequences such as \"../\". For example, after applying this filter to \".../...//\" the resulting string would still be \"../\".\n* Use a whitelist of known good patterns.\n* Sanitize potentially tainted paths using `HttpRequest.MapPath`.\n\n## Example\nIn the first example, a file name is read from a `HttpRequest` and then used to access a file. However, a malicious user could enter a file name which is an absolute path - for example, \"/etc/passwd\". In the second example, it appears that the user is restricted to opening a file within the \"user\" home directory. However, a malicious user could enter a filename which contains special characters. For example, the string \"../../etc/passwd\" will result in the code reading the file located at \"/home/\\[user\\]/../../etc/passwd\", which is the system's password file. This file would then be sent back to the user, giving them access to all the system's passwords.\n\n\n```csharp\nusing System;\nusing System.IO;\nusing System.Web;\n\npublic class TaintedPathHandler : IHttpHandler\n{\n    public void ProcessRequest(HttpContext ctx)\n    {\n        String path = ctx.Request.QueryString[\"path\"];\n        // BAD: This could read any file on the filesystem.\n        ctx.Response.Write(File.ReadAllText(path));\n\n        // BAD: This could still read any file on the filesystem.\n        ctx.Response.Write(File.ReadAllText(\"/home/user/\" + path));\n\n        // GOOD: MapPath ensures the path is safe to read from.\n        string safePath = ctx.Request.MapPath(path, ctx.Request.ApplicationPath, false);\n        ctx.Response.Write(File.ReadAllText(safePath));\n    }\n}\n\n```\n\n## References\n* OWASP: [Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal).\n* Common Weakness Enumeration: [CWE-22](https://cwe.mitre.org/data/definitions/22.html).\n* Common Weakness Enumeration: [CWE-23](https://cwe.mitre.org/data/definitions/23.html).\n* Common Weakness Enumeration: [CWE-36](https://cwe.mitre.org/data/definitions/36.html).\n* Common Weakness Enumeration: [CWE-73](https://cwe.mitre.org/data/definitions/73.html).\n* Common Weakness Enumeration: [CWE-99](https://cwe.mitre.org/data/definitions/99.html).\n",
									"text": "# Uncontrolled data used in path expression\nAccessing paths controlled by users can allow an attacker to access unexpected resources. This can result in sensitive information being revealed or deleted, or an attacker being able to influence behavior by modifying unexpected files.\n\nPaths that are naively constructed from data controlled by a user may contain unexpected special characters, such as \"..\". Such a path may potentially point to any directory on the file system.\n\n\n## Recommendation\nValidate user input before using it to construct a file path. Ideally, follow these rules:\n\n* Do not allow more than a single \".\" character.\n* Do not allow directory separators such as \"/\" or \"\\\\\" (depending on the file system).\n* Do not rely on simply replacing problematic sequences such as \"../\". For example, after applying this filter to \".../...//\" the resulting string would still be \"../\".\n* Use a whitelist of known good patterns.\n* Sanitize potentially tainted paths using `HttpRequest.MapPath`.\n\n## Example\nIn the first example, a file name is read from a `HttpRequest` and then used to access a file. However, a malicious user could enter a file name which is an absolute path - for example, \"/etc/passwd\". In the second example, it appears that the user is restricted to opening a file within the \"user\" home directory. However, a malicious user could enter a filename which contains special characters. For example, the string \"../../etc/passwd\" will result in the code reading the file located at \"/home/\\[user\\]/../../etc/passwd\", which is the system's password file. This file would then be sent back to the user, giving them access to all the system's passwords.\n\n\n```csharp\nusing System;\nusing System.IO;\nusing System.Web;\n\npublic class TaintedPathHandler : IHttpHandler\n{\n    public void ProcessRequest(HttpContext ctx)\n    {\n        String path = ctx.Request.QueryString[\"path\"];\n        // BAD: This could read any file on the filesystem.\n        ctx.Response.Write(File.ReadAllText(path));\n\n        // BAD: This could still read any file on the filesystem.\n        ctx.Response.Write(File.ReadAllText(\"/home/user/\" + path));\n\n        // GOOD: MapPath ensures the path is safe to read from.\n        string safePath = ctx.Request.MapPath(path, ctx.Request.ApplicationPath, false);\n        ctx.Response.Write(File.ReadAllText(safePath));\n    }\n}\n\n```\n\n## References\n* OWASP: [Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal).\n* Common Weakness Enumeration: [CWE-22](https://cwe.mitre.org/data/definitions/22.html).\n* Common Weakness Enumeration: [CWE-23](https://cwe.mitre.org/data/definitions/23.html).\n* Common Weakness Enumeration: [CWE-36](https://cwe.mitre.org/data/definitions/36.html).\n* Common Weakness Enumeration: [CWE-73](https://cwe.mitre.org/data/definitions/73.html).\n* Common Weakness Enumeration: [CWE-99](https://cwe.mitre.org/data/definitions/99.html).\n"
								},
								"id": "cs/path-injection",
								"name": "cs/path-injection",
								"properties": {
									"precision": "high",
									"queryURI": "https://github.com/github/codeql/blob/f30b735443ec9f7528b51628a16510dce4ea0a56/csharp/ql/src/Security%20Features/CWE-022/TaintedPath.ql",
									"security-severity": "7.500000",
									"tags": [
										"external/cwe/cwe-022",
										"external/cwe/cwe-023",
										"external/cwe/cwe-036",
										"external/cwe/cwe-073",
										"external/cwe/cwe-099",
										"security"
									]
								},
								"shortDescription": {
									"text": "Uncontrolled data used in path expression"
								}
							},
							{
								"defaultConfiguration": {
									"level": "error"
								},
								"fullDescription": {
									"text": "User input should not be used in regular expressions without first being escaped, otherwise a malicious user may be able to provide a regex that could require exponential time on certain inputs."
								},
								"help": {
									"markdown": "# Regular expression injection\nConstructing a regular expression with unsanitized user input is dangerous as a malicious user may be able to modify the meaning of the expression. In particular, such a user may be able to provide a regular expression fragment that takes exponential time in the worst case, and use that to perform a Denial of Service attack.\n\n\n## Recommendation\nFor user input that is intended to be referenced as a string literal in a regular expression, use the `Regex.Escape` method to escape any special characters. If the regular expression is intended to be configurable by the user, then a timeout should be used to avoid Denial of Service attacks. For C\\# applications, a timeout can be provided to the `Regex` constructor. Alternatively, apply a global timeout by setting the `REGEX_DEFAULT_MATCH_TIMEOUT` application domain property, using the `AppDomain.SetData` method.\n\n\n## Example\nThe following example shows a HTTP request parameter that is used as a regular expression, and matched against another request parameter.\n\nIn the first case, the regular expression is used without a timeout, and the user-provided regex is not escaped. If a malicious user provides a regex that has exponential worst case performance, then this could lead to a Denial of Service.\n\nIn the second case, the user input is escaped using `Regex.Escape` before being included in the regular expression. This ensures that the user cannot insert characters which have a special meaning in regular expressions.\n\n\n```csharp\nusing System;\nusing System.Web;\nusing System.Text.RegularExpressions;\n\npublic class RegexInjectionHandler : IHttpHandler\n{\n\n    public void ProcessRequest(HttpContext ctx)\n    {\n        string name = ctx.Request.QueryString[\"name\"];\n        string userInput = ctx.Request.QueryString[\"userInput\"];\n\n        // BAD: Unsanitized user input is used to construct a regular expression\n        new Regex(\"^\" + name + \"=.*$\").Match(userInput);\n\n        // GOOD: User input is sanitized before constructing the regex\n        string safeName = Regex.Escape(name);\n        new Regex(\"^\" + safeName + \"=.*$\").Match(userInput);\n    }\n}\n\n```\n\n## References\n* OWASP: [Regular expression Denial of Service - ReDoS](https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS).\n* Wikipedia: [ReDoS](https://en.wikipedia.org/wiki/ReDoS).\n* Common Weakness Enumeration: [CWE-730](https://cwe.mitre.org/data/definitions/730.html).\n* Common Weakness Enumeration: [CWE-400](https://cwe.mitre.org/data/definitions/400.html).\n",
									"text": "# Regular expression injection\nConstructing a regular expression with unsanitized user input is dangerous as a malicious user may be able to modify the meaning of the expression. In particular, such a user may be able to provide a regular expression fragment that takes exponential time in the worst case, and use that to perform a Denial of Service attack.\n\n\n## Recommendation\nFor user input that is intended to be referenced as a string literal in a regular expression, use the `Regex.Escape` method to escape any special characters. If the regular expression is intended to be configurable by the user, then a timeout should be used to avoid Denial of Service attacks. For C\\# applications, a timeout can be provided to the `Regex` constructor. Alternatively, apply a global timeout by setting the `REGEX_DEFAULT_MATCH_TIMEOUT` application domain property, using the `AppDomain.SetData` method.\n\n\n## Example\nThe following example shows a HTTP request parameter that is used as a regular expression, and matched against another request parameter.\n\nIn the first case, the regular expression is used without a timeout, and the user-provided regex is not escaped. If a malicious user provides a regex that has exponential worst case performance, then this could lead to a Denial of Service.\n\nIn the second case, the user input is escaped using `Regex.Escape` before being included in the regular expression. This ensures that the user cannot insert characters which have a special meaning in regular expressions.\n\n\n```csharp\nusing System;\nusing System.Web;\nusing System.Text.RegularExpressions;\n\npublic class RegexInjectionHandler : IHttpHandler\n{\n\n    public void ProcessRequest(HttpContext ctx)\n    {\n        string name = ctx.Request.QueryString[\"name\"];\n        string userInput = ctx.Request.QueryString[\"userInput\"];\n\n        // BAD: Unsanitized user input is used to construct a regular expression\n        new Regex(\"^\" + name + \"=.*$\").Match(userInput);\n\n        // GOOD: User input is sanitized before constructing the regex\n        string safeName = Regex.Escape(name);\n        new Regex(\"^\" + safeName + \"=.*$\").Match(userInput);\n    }\n}\n\n```\n\n## References\n* OWASP: [Regular expression Denial of Service - ReDoS](https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS).\n* Wikipedia: [ReDoS](https://en.wikipedia.org/wiki/ReDoS).\n* Common Weakness Enumeration: [CWE-730](https://cwe.mitre.org/data/definitions/730.html).\n* Common Weakness Enumeration: [CWE-400](https://cwe.mitre.org/data/definitions/400.html).\n"
								},
								"id": "cs/regex-injection",
								"name": "cs/regex-injection",
								"properties": {
									"precision": "high",
									"queryURI": "https://github.com/github/codeql/blob/f30b735443ec9f7528b51628a16510dce4ea0a56/csharp/ql/src/Security%20Features/CWE-730/RegexInjection.ql",
									"security-severity": "7.500000",
									"tags": [
										"external/cwe/cwe-400",
										"external/cwe/cwe-730",
										"security"
									]
								},
								"shortDescription": {
									"text": "Regular expression injection"
								}
							},
							{
								"defaultConfiguration": {
									"level": "error"
								},
								"fullDescription": {
									"text": "Building a SQL query from user-controlled sources is vulnerable to insertion of malicious SQL code by the user."
								},
								"help": {
									"markdown": "# SQL query built from user-controlled sources\nIf a SQL query is built using string concatenation, and the components of the concatenation include user input, a user is likely to be able to run malicious database queries.\n\n\n## Recommendation\nUsually, it is better to use a prepared statement than to build a complete query with string concatenation. A prepared statement can include a parameter, written as either a question mark (`?`) or with an explicit name (`@parameter`), for each part of the SQL query that is expected to be filled in by a different value each time it is run. When the query is later executed, a value must be supplied for each parameter in the query.\n\nIt is good practice to use prepared statements for supplying parameters to a query, whether or not any of the parameters are directly traceable to user input. Doing so avoids any need to worry about quoting and escaping.\n\n\n## Example\nIn the following example, the code runs a simple SQL query in three different ways.\n\nThe first way involves building a query, `query1`, by concatenating a user-supplied text box value with some string literals. The text box value can include special characters, so this code allows for SQL injection attacks.\n\nThe second way uses a stored procedure, `ItemsStoredProcedure`, with a single parameter (`@category`). The parameter is then given a value by calling `Parameters.Add`. This version is immune to injection attacks, because any special characters are not given any special treatment.\n\nThe third way builds a query, `query2`, with a single string literal that includes a parameter (`@category`). The parameter is then given a value by calling `Parameters.Add`. This version is immune to injection attacks, because any special characters are not given any special treatment.\n\n\n```csharp\nusing System.Data;\nusing System.Data.SqlClient;\nusing System.Web.UI.WebControls;\n\nclass SqlInjection\n{\n    TextBox categoryTextBox;\n    string connectionString;\n\n    public DataSet GetDataSetByCategory()\n    {\n        // BAD: the category might have SQL special characters in it\n        using (var connection = new SqlConnection(connectionString))\n        {\n            var query1 = \"SELECT ITEM,PRICE FROM PRODUCT WHERE ITEM_CATEGORY='\"\n              + categoryTextBox.Text + \"' ORDER BY PRICE\";\n            var adapter = new SqlDataAdapter(query1, connection);\n            var result = new DataSet();\n            adapter.Fill(result);\n            return result;\n        }\n\n        // GOOD: use parameters with stored procedures\n        using (var connection = new SqlConnection(connectionString))\n        {\n            var adapter = new SqlDataAdapter(\"ItemsStoredProcedure\", connection);\n            adapter.SelectCommand.CommandType = CommandType.StoredProcedure;\n            var parameter = new SqlParameter(\"category\", categoryTextBox.Text);\n            adapter.SelectCommand.Parameters.Add(parameter);\n            var result = new DataSet();\n            adapter.Fill(result);\n            return result;\n        }\n\n        // GOOD: use parameters with dynamic SQL\n        using (var connection = new SqlConnection(connectionString))\n        {\n            var query2 = \"SELECT ITEM,PRICE FROM PRODUCT WHERE ITEM_CATEGORY=\"\n              + \"@category ORDER BY PRICE\";\n            var adapter = new SqlDataAdapter(query2, connection);\n            var parameter = new SqlParameter(\"category\", categoryTextBox.Text);\n            adapter.SelectCommand.Parameters.Add(parameter);\n            var result = new DataSet();\n            adapter.Fill(result);\n            return result;\n        }\n    }\n}\n\n```\n\n## References\n* MSDN: [How To: Protect From SQL Injection in ASP.NET](https://msdn.microsoft.com/en-us/library/ff648339.aspx).\n* Common Weakness Enumeration: [CWE-89](https://cwe.mitre.org/data/definitions/89.html).\n",
									"text": "# SQL query built from user-controlled sources\nIf a SQL query is built using string concatenation, and the components of the concatenation include user input, a user is likely to be able to run malicious database queries.\n\n\n## Recommendation\nUsually, it is better to use a prepared statement than to build a complete query with string concatenation. A prepared statement can include a parameter, written as either a question mark (`?`) or with an explicit name (`@parameter`), for each part of the SQL query that is expected to be filled in by a different value each time it is run. When the query is later executed, a value must be supplied for each parameter in the query.\n\nIt is good practice to use prepared statements for supplying parameters to a query, whether or not any of the parameters are directly traceable to user input. Doing so avoids any need to worry about quoting and escaping.\n\n\n## Example\nIn the following example, the code runs a simple SQL query in three different ways.\n\nThe first way involves building a query, `query1`, by concatenating a user-supplied text box value with some string literals. The text box value can include special characters, so this code allows for SQL injection attacks.\n\nThe second way uses a stored procedure, `ItemsStoredProcedure`, with a single parameter (`@category`). The parameter is then given a value by calling `Parameters.Add`. This version is immune to injection attacks, because any special characters are not given any special treatment.\n\nThe third way builds a query, `query2`, with a single string literal that includes a parameter (`@category`). The parameter is then given a value by calling `Parameters.Add`. This version is immune to injection attacks, because any special characters are not given any special treatment.\n\n\n```csharp\nusing System.Data;\nusing System.Data.SqlClient;\nusing System.Web.UI.WebControls;\n\nclass SqlInjection\n{\n    TextBox categoryTextBox;\n    string connectionString;\n\n    public DataSet GetDataSetByCategory()\n    {\n        // BAD: the category might have SQL special characters in it\n        using (var connection = new SqlConnection(connectionString))\n        {\n            var query1 = \"SELECT ITEM,PRICE FROM PRODUCT WHERE ITEM_CATEGORY='\"\n              + categoryTextBox.Text + \"' ORDER BY PRICE\";\n            var adapter = new SqlDataAdapter(query1, connection);\n            var result = new DataSet();\n            adapter.Fill(result);\n            return result;\n        }\n\n        // GOOD: use parameters with stored procedures\n        using (var connection = new SqlConnection(connectionString))\n        {\n            var adapter = new SqlDataAdapter(\"ItemsStoredProcedure\", connection);\n            adapter.SelectCommand.CommandType = CommandType.StoredProcedure;\n            var parameter = new SqlParameter(\"category\", categoryTextBox.Text);\n            adapter.SelectCommand.Parameters.Add(parameter);\n            var result = new DataSet();\n            adapter.Fill(result);\n            return result;\n        }\n\n        // GOOD: use parameters with dynamic SQL\n        using (var connection = new SqlConnection(connectionString))\n        {\n            var query2 = \"SELECT ITEM,PRICE FROM PRODUCT WHERE ITEM_CATEGORY=\"\n              + \"@category ORDER BY PRICE\";\n            var adapter = new SqlDataAdapter(query2, connection);\n            var parameter = new SqlParameter(\"category\", categoryTextBox.Text);\n            adapter.SelectCommand.Parameters.Add(parameter);\n            var result = new DataSet();\n            adapter.Fill(result);\n            return result;\n        }\n    }\n}\n\n```\n\n## References\n* MSDN: [How To: Protect From SQL Injection in ASP.NET](https://msdn.microsoft.com/en-us/library/ff648339.aspx).\n* Common Weakness Enumeration: [CWE-89](https://cwe.mitre.org/data/definitions/89.html).\n"
								},
								"id": "cs/sql-injection",
								"name": "cs/sql-injection",
								"properties": {
									"precision": "high",
									"queryURI": "https://github.com/github/codeql/blob/f30b735443ec9f7528b51628a16510dce4ea0a56/csharp/ql/src/Security%20Features/CWE-089/SqlInjection.ql",
									"security-severity": "8.800000",
									"tags": [
										"external/cwe/cwe-089",
										"security"
									]
								},
								"shortDescription": {
									"text": "SQL query built from user-controlled sources"
								}
							}
						],
						"semanticVersion": "0.3.2+f30b735443ec9f7528b51628a16510dce4ea0a56"
					}
				]
			},
			"versionControlProvenance": [
				{
					"branch": "refs/heads/main",
					"repositoryUri": "https://github.com/microsoft/sarif-testing",
					"revisionId": "e019fdfbe46d4f43d3f803edb9cbf2ec6b780e20"
				}
			]
		}
	],
	"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
	"version": "2.1.0"
}

if (lines[14 - 1] === '            return System.IO.File.ReadAllText(path);') {
	log.runs[0].results.push(results[0]);
}
if (lines[20 - 1] === '            Match match = Regex.Match(data, "^term=" + token);') {
	log.runs[0].results.push(results[1]);
}
if (lines[29 - 1] === '            using var conn = new SqlConnection("my-connection-string");') {
	log.runs[0].results.push(results[2]);
}
if (lines[31 - 1] === '            cmd.CommandText = sql;') {
	log.runs[0].results.push(results[3]);
}

writeFileSync('results.sarif', JSON.stringify(log, null, 4))

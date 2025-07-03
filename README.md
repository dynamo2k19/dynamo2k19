
# SOQL Injection Attack Demonstration

This repository contains comprehensive examples demonstrating SOQL injection vulnerabilities and how to prevent them in Salesforce Apex development.

## Files Overview

### 1. `SOQLInjectionDemo.cls`
The main demonstration class containing:
- **Vulnerable code examples** showing common SOQL injection patterns
- **Attack simulations** demonstrating how exploits work
- **Secure implementations** using proper prevention techniques
- **Utility methods** for input sanitization and secure query building

### 2. `SOQLInjectionDemoTest.cls`
Comprehensive test class featuring:
- Unit tests for all secure methods
- Security penetration testing scenarios
- Performance testing of secure implementations
- Input validation and sanitization tests
- Compliance and audit verification tests

### 3. `SOQL_Injection_Guide.md`
Detailed documentation covering:
- What SOQL injection is and its impact
- Common vulnerability patterns
- Step-by-step attack examples
- Prevention techniques and best practices
- Testing methodologies
- Additional security resources

## Key Learning Points

### Vulnerable Patterns to Avoid
```apex
// DON'T DO THIS - Vulnerable to injection
String query = 'SELECT Id FROM Account WHERE Name = \'' + userInput + '\'';
```

### Secure Approaches to Use
```apex
// DO THIS - Use bind variables
String query = 'SELECT Id FROM Account WHERE Name = :userInput';

// OR THIS - Validate and whitelist dynamic fields
Set<String> allowedFields = new Set<String>{'Name', 'Type'};
if (allowedFields.contains(fieldName)) {
    String query = 'SELECT Id FROM Account ORDER BY ' + fieldName;
}
```

## Security Prevention Techniques Demonstrated

1. **Bind Variables**: Complete separation of code and data
2. **Input Validation**: Whitelisting allowed values
3. **String Escaping**: Using `String.escapeSingleQuotes()`
4. **Schema Validation**: Verifying field/object existence
5. **Input Sanitization**: Removing dangerous characters and keywords

## How to Use This Demo

1. **Review the vulnerable code** in `SOQLInjectionDemo.cls` to understand common mistakes
2. **Study the attack examples** to see how exploits work
3. **Examine the secure implementations** to learn proper techniques
4. **Run the test class** to verify security measures work correctly
5. **Read the guide** for comprehensive understanding

## Running the Tests

Deploy the files to a Salesforce org and run:

```apex
// Execute all security tests
Test.runTests([SOQLInjectionDemoTest.class]);

// Try the demonstration methods (safely)
SOQLInjectionDemo.testSecureImplementations();
SOQLInjectionDemo.demonstrateAttacks();
```

## Security Checklist

When writing SOQL queries, always:

- ✅ Use bind variables (`:variableName`) for user input
- ✅ Validate dynamic field/object names against whitelists
- ✅ Use `String.escapeSingleQuotes()` when bind variables aren't suitable
- ✅ Implement proper input sanitization
- ✅ Test with malicious input patterns
- ❌ Never concatenate user input directly into query strings
- ❌ Don't trust user input for field or object names without validation

## Educational Purpose

This demonstration is created for educational purposes to:
- Raise awareness about SOQL injection vulnerabilities
- Teach secure coding practices in Salesforce development
- Provide practical examples of attack and defense techniques
- Help developers write more secure Apex code

**Warning**: The vulnerable code examples should never be used in production environments.

## Additional Resources

- [Salesforce Security Developer Guide](https://developer.salesforce.com/docs/atlas.en-us.secure_coding_guide.meta/secure_coding_guide/)
- [OWASP SQL Injection Prevention](https://owasp.org/www-community/attacks/SQL_Injection)
- [Apex Security Guidelines](https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_security_guidelines.htm)

---

Remember: **Security is not optional** - always validate and sanitize user input!

<!---
dynamo2k19/dynamo2k19 is a ✨ special ✨ repository because its `README.md` (this file) appears on your GitHub profile.
You can click the Preview link to take a look at your changes.
--->

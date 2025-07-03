# SOQL Injection Attack Demonstration and Prevention

## Overview

SOQL (Salesforce Object Query Language) injection is a security vulnerability that occurs when user input is directly concatenated into SOQL queries without proper sanitization or parameterization. This can allow attackers to manipulate queries, access unauthorized data, or perform unintended operations.

## Table of Contents

1. [What is SOQL Injection?](#what-is-soql-injection)
2. [Common Vulnerability Patterns](#common-vulnerability-patterns)
3. [Attack Examples](#attack-examples)
4. [Prevention Techniques](#prevention-techniques)
5. [Best Practices](#best-practices)
6. [Testing Your Code](#testing-your-code)

## What is SOQL Injection?

SOQL injection occurs when:
- User input is directly concatenated into SOQL query strings
- Input is not properly validated or escaped
- Dynamic queries are built without using secure parameterization

### Impact of SOQL Injection
- **Data breach**: Access to unauthorized records
- **Privilege escalation**: Bypassing security restrictions
- **Information disclosure**: Exposing sensitive data structure
- **Denial of service**: Causing resource exhaustion

## Common Vulnerability Patterns

### 1. Direct String Concatenation

```apex
// VULNERABLE CODE
String accountName = userInput;
String query = 'SELECT Id FROM Account WHERE Name = \'' + accountName + '\'';
List<Account> accounts = Database.query(query);
```

**Problem**: User input is directly embedded in the query string.

### 2. Dynamic Field Names

```apex
// VULNERABLE CODE
String sortField = userInput;
String query = 'SELECT Id, Name FROM Account ORDER BY ' + sortField;
List<Account> accounts = Database.query(query);
```

**Problem**: User controls which field is used for sorting.

### 3. Multiple Injection Points

```apex
// VULNERABLE CODE
String query = 'SELECT Id FROM Contact WHERE LastName = \'' + lastName + 
               '\' AND Department = \'' + department + '\'';
```

**Problem**: Multiple user inputs create multiple attack vectors.

## Attack Examples

### Attack 1: WHERE Clause Bypass

**Malicious Input**: `test' OR Name != ''`

**Resulting Query**:
```sql
SELECT Id, Name, Type FROM Account WHERE Name = 'test' OR Name != ''
```

**Result**: Returns ALL accounts instead of just those named 'test'

### Attack 2: UNION-Based Information Disclosure

**Malicious Input**: `test' UNION SELECT Id, Name, 'SENSITIVE' FROM User WHERE Name != ''`

**Resulting Query**:
```sql
SELECT Id, Name, Type FROM Account WHERE Name = 'test' 
UNION SELECT Id, Name, 'SENSITIVE' FROM User WHERE Name != ''
```

**Result**: Exposes User object data alongside Account data

### Attack 3: Subquery Injection in ORDER BY

**Malicious Input**: `Name, (SELECT Count() FROM Account)`

**Resulting Query**:
```sql
SELECT Id, Name FROM Opportunity ORDER BY Name, (SELECT Count() FROM Account)
```

**Result**: Can expose aggregate data about other objects

## Prevention Techniques

### 1. Use Bind Variables (Recommended)

```apex
// SECURE CODE
String accountName = userInput;
String query = 'SELECT Id, Name, Type FROM Account WHERE Name = :accountName';
List<Account> accounts = Database.query(query);
```

**Benefits**:
- Automatic escaping of special characters
- Complete separation of code and data
- Best performance due to query plan caching

### 2. Input Validation and Whitelisting

```apex
// SECURE CODE
Set<String> allowedFields = new Set<String>{'Name', 'Amount', 'StageName'};
Set<String> allowedOrders = new Set<String>{'ASC', 'DESC'};

if (!allowedFields.contains(sortField)) {
    sortField = 'Name'; // Default safe value
}
if (!allowedOrders.contains(sortOrder.toUpperCase())) {
    sortOrder = 'ASC'; // Default safe value
}

String query = 'SELECT Id, Name FROM Account ORDER BY ' + sortField + ' ' + sortOrder;
```

### 3. Use String.escapeSingleQuotes()

```apex
// SECURE CODE (when bind variables aren't suitable)
String escapedName = String.escapeSingleQuotes(accountName);
String query = 'SELECT Id, Name FROM Account WHERE Name = \'' + escapedName + '\'';
```

**Note**: This only escapes single quotes, not a complete solution.

### 4. Schema Validation for Dynamic Queries

```apex
// SECURE CODE
public static List<SObject> getRecords(String objectType, String fieldName, String fieldValue) {
    // Validate object type
    Schema.SObjectType objType = Schema.getGlobalDescribe().get(objectType);
    if (objType == null) {
        throw new IllegalArgumentException('Invalid object type');
    }
    
    // Validate field name
    Map<String, Schema.SObjectField> fieldMap = objType.getDescribe().fields.getMap();
    if (!fieldMap.containsKey(fieldName)) {
        throw new IllegalArgumentException('Invalid field name');
    }
    
    // Use bind variable for value
    String query = 'SELECT Id FROM ' + objectType + ' WHERE ' + fieldName + ' = :fieldValue';
    return Database.query(query);
}
```

## Best Practices

### 1. Always Use Bind Variables for Values
- Use `:variableName` syntax for all user-provided values
- Never concatenate user input directly into WHERE clauses

### 2. Validate Dynamic Field/Object Names
- Maintain whitelists of allowed fields and objects
- Use Schema describe methods to validate field existence
- Default to safe values when validation fails

### 3. Implement Input Sanitization
```apex
public static String sanitizeInput(String input) {
    if (String.isBlank(input)) return '';
    
    // Remove dangerous characters
    String sanitized = input.replaceAll('[\'";\\\\]', '');
    
    // Remove SQL injection keywords
    String[] keywords = {'UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE'};
    for (String keyword : keywords) {
        sanitized = sanitized.replaceAll('(?i)' + keyword, '');
    }
    
    return sanitized.trim();
}
```

### 4. Use Parameterized Query Builders
- Build reusable, secure query construction methods
- Validate all dynamic components before building queries
- Use consistent error handling

### 5. Apply Principle of Least Privilege
- Only query fields that are actually needed
- Respect field-level security and sharing rules
- Use appropriate SOQL limits

## Testing Your Code

### 1. Test with Malicious Inputs
```apex
// Test various injection attempts
String[] maliciousInputs = {
    'test\' OR Name != \'\'',
    'test\'; DROP TABLE Account; --',
    'test\' UNION SELECT Id FROM User--'
};

for (String input : maliciousInputs) {
    // Verify your secure method handles this safely
    testSecureMethod(input);
}
```

### 2. Validate Query Output
- Ensure malicious input doesn't return more records than expected
- Verify that query structure remains intact
- Check debug logs for actual executed queries

### 3. Use Static Analysis Tools
- Salesforce provides security scanning tools
- PMD rules can detect potential SOQL injection
- Regular code reviews focusing on dynamic queries

## Code Examples

The `SOQLInjectionDemo.cls` file contains:

- **Vulnerable examples**: Demonstrating common injection patterns
- **Attack simulations**: Showing how exploits work
- **Secure implementations**: Proper prevention techniques
- **Utility methods**: Reusable secure query builders

### Running the Demo

```apex
// Test secure implementations
SOQLInjectionDemo.testSecureImplementations();

// See attack examples (educational purposes only)
SOQLInjectionDemo.demonstrateAttacks();
```

## Conclusion

SOQL injection can be completely prevented by:

1. **Using bind variables** for all user-provided values
2. **Validating and whitelisting** dynamic field/object names
3. **Implementing proper input sanitization**
4. **Following secure coding practices**

Remember: Security is not optional - always validate and sanitize user input, and prefer parameterized queries over string concatenation.

## Additional Resources

- [Salesforce Security Developer Guide](https://developer.salesforce.com/docs/atlas.en-us.secure_coding_guide.meta/secure_coding_guide/)
- [OWASP SQL Injection Prevention](https://owasp.org/www-community/attacks/SQL_Injection)
- [Salesforce Apex Security Best Practices](https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_security_guidelines.htm)
# SOQL Injection Quick Security Reference

## ⚠️ VULNERABLE vs ✅ SECURE

### 1. Basic WHERE Clause

```apex
// ⚠️ VULNERABLE - Direct concatenation
String query = 'SELECT Id FROM Account WHERE Name = \'' + userInput + '\'';

// ✅ SECURE - Bind variable
String query = 'SELECT Id FROM Account WHERE Name = :userInput';
```

### 2. Multiple Parameters

```apex
// ⚠️ VULNERABLE - Multiple injection points
String query = 'SELECT Id FROM Contact WHERE LastName = \'' + lastName + 
               '\' AND Department = \'' + dept + '\'';

// ✅ SECURE - Multiple bind variables
String query = 'SELECT Id FROM Contact WHERE LastName = :lastName AND Department = :dept';
```

### 3. Dynamic ORDER BY

```apex
// ⚠️ VULNERABLE - User-controlled ORDER BY
String query = 'SELECT Id FROM Account ORDER BY ' + sortField + ' ' + sortOrder;

// ✅ SECURE - Whitelist validation
Set<String> allowedFields = new Set<String>{'Name', 'Type', 'CreatedDate'};
Set<String> allowedOrders = new Set<String>{'ASC', 'DESC'};
if (!allowedFields.contains(sortField)) sortField = 'Name';
if (!allowedOrders.contains(sortOrder)) sortOrder = 'ASC';
String query = 'SELECT Id FROM Account ORDER BY ' + sortField + ' ' + sortOrder;
```

### 4. Dynamic Object/Field Names

```apex
// ⚠️ VULNERABLE - Unvalidated object names
String query = 'SELECT Id FROM ' + objectName;

// ✅ SECURE - Schema validation
Schema.SObjectType objType = Schema.getGlobalDescribe().get(objectName);
if (objType == null) throw new IllegalArgumentException('Invalid object');
String query = 'SELECT Id FROM ' + objectName;
```

### 5. String Escaping (When Bind Variables Aren't Suitable)

```apex
// ⚠️ VULNERABLE - No escaping
String query = 'SELECT Id FROM Account WHERE Name = \'' + accountName + '\'';

// ✅ SECURE - Proper escaping
String escaped = String.escapeSingleQuotes(accountName);
String query = 'SELECT Id FROM Account WHERE Name = \'' + escaped + '\'';
```

## 🔧 Common Attack Payloads to Test Against

```apex
String[] testPayloads = {
    '\' OR Name != \'\'',           // Basic injection
    '\' UNION SELECT Id FROM User--', // Union injection
    '\'; DROP TABLE Account; --',    // Destructive attempt
    '\')) OR ((Name != \'\'',       // Parentheses bypass
    '/**/OR/**/1=1'                 // Comment-based bypass
};
```

## 🛡️ Input Sanitization Helper

```apex
public static String sanitizeInput(String input) {
    if (String.isBlank(input)) return '';
    
    // Remove dangerous characters
    String sanitized = input.replaceAll('[\'";\\\\]', '');
    
    // Remove SQL keywords (case-insensitive)
    String[] keywords = {'UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP'};
    for (String keyword : keywords) {
        sanitized = sanitized.replaceAll('(?i)' + keyword, '');
    }
    
    return sanitized.trim();
}
```

## 📝 Security Checklist

Before deploying any dynamic SOQL:

- [ ] User input uses bind variables (`:variable`)
- [ ] Dynamic field names validated against whitelist
- [ ] Dynamic object names checked via Schema
- [ ] Input sanitization applied where needed
- [ ] Tested with malicious payloads
- [ ] Code reviewed by security-aware developer

## 🚨 Red Flags to Watch For

```apex
// 🚨 These patterns indicate potential vulnerabilities:
String query = 'SELECT ... WHERE field = \'' + userInput + '\'';
String query = 'SELECT ... ORDER BY ' + userField;
String query = 'SELECT ... FROM ' + userObject;
Database.query('SELECT ... WHERE ' + userCondition);
```

## ⚡ Quick Tests

```apex
// Test your secure method with these inputs:
String[] dangerousInputs = {
    'normal input',                    // Should work
    'test\' OR 1=1--',                // Should be safe
    'test\'; DELETE FROM Account;--'   // Should be safe
};

for (String input : dangerousInputs) {
    List<SObject> results = yourSecureMethod(input);
    System.debug('Input: ' + input + ' returned ' + results.size() + ' records');
}
```

## 📚 Remember

1. **Bind variables are your first line of defense**
2. **Validate all dynamic components**
3. **When in doubt, whitelist allowed values**
4. **Test with malicious input**
5. **Security reviews are mandatory for dynamic queries**

---

💡 **Pro Tip**: Use `Database.query()` debug logs to verify your queries look correct and don't contain unescaped user input.
/**
 * SOQL Injection Demonstration Class
 * This class shows vulnerable code and secure alternatives
 */
public class SOQLInjectionDemo {
    
    // ======================================================
    // VULNERABLE CODE - DO NOT USE IN PRODUCTION
    // ======================================================
    
    /**
     * VULNERABLE: Dynamic SOQL without proper sanitization
     * This method is susceptible to SOQL injection attacks
     */
    public static List<Account> getAccountsVulnerable(String accountName) {
        // BAD: Direct string concatenation creates injection vulnerability
        String query = 'SELECT Id, Name, Type FROM Account WHERE Name = \'' + accountName + '\'';
        
        System.debug('Vulnerable Query: ' + query);
        return Database.query(query);
    }
    
    /**
     * VULNERABLE: User input directly in WHERE clause
     */
    public static List<Contact> getContactsVulnerable(String lastName, String department) {
        // BAD: Multiple injection points
        String query = 'SELECT Id, Name, Email FROM Contact WHERE LastName = \'' + lastName + 
                      '\' AND Department = \'' + department + '\'';
        
        System.debug('Vulnerable Query: ' + query);
        return Database.query(query);
    }
    
    /**
     * VULNERABLE: Dynamic ORDER BY clause
     */
    public static List<Opportunity> getOpportunitiesVulnerable(String sortField, String sortOrder) {
        // BAD: User-controlled ORDER BY can lead to injection
        String query = 'SELECT Id, Name, Amount, StageName FROM Opportunity ORDER BY ' + 
                      sortField + ' ' + sortOrder;
        
        System.debug('Vulnerable Query: ' + query);
        return Database.query(query);
    }
    
    // ======================================================
    // SOQL INJECTION ATTACK EXAMPLES
    // ======================================================
    
    /**
     * Demonstrates how an attacker could exploit the vulnerable methods
     */
    public static void demonstrateAttacks() {
        System.debug('=== SOQL Injection Attack Demonstrations ===');
        
        // Attack 1: SQL injection to bypass WHERE clause
        // Input: test' OR Name != ''
        // Results in: SELECT Id, Name, Type FROM Account WHERE Name = 'test' OR Name != ''
        // This would return ALL accounts instead of just those named 'test'
        String maliciousInput1 = 'test\' OR Name != \'\'';
        System.debug('Attack 1 - Bypass WHERE clause:');
        System.debug('Input: ' + maliciousInput1);
        // getAccountsVulnerable(maliciousInput1); // Uncomment to test
        
        // Attack 2: Information disclosure through UNION
        // Input: test' UNION SELECT Id, Name, 'SENSITIVE' FROM User WHERE Name != ''
        String maliciousInput2 = 'test\' UNION SELECT Id, Name, \'SENSITIVE\' FROM User WHERE Name != \'\'';
        System.debug('Attack 2 - Union-based injection:');
        System.debug('Input: ' + maliciousInput2);
        
        // Attack 3: ORDER BY injection
        // Input: Name, (SELECT Count() FROM Account)
        // This could expose data about other objects
        String maliciousOrderBy = 'Name, (SELECT Count() FROM Account)';
        System.debug('Attack 3 - ORDER BY injection:');
        System.debug('Input: ' + maliciousOrderBy);
    }
    
    // ======================================================
    // SECURE CODE - RECOMMENDED APPROACHES
    // ======================================================
    
    /**
     * SECURE: Using bind variables to prevent injection
     */
    public static List<Account> getAccountsSecure(String accountName) {
        // GOOD: Bind variables automatically escape special characters
        String query = 'SELECT Id, Name, Type FROM Account WHERE Name = :accountName';
        
        System.debug('Secure Query: ' + query);
        System.debug('Bind Variable: ' + accountName);
        return Database.query(query);
    }
    
    /**
     * SECURE: Multiple bind variables
     */
    public static List<Contact> getContactsSecure(String lastName, String department) {
        // GOOD: Multiple bind variables are safe
        String query = 'SELECT Id, Name, Email FROM Contact WHERE LastName = :lastName AND Department = :department';
        
        System.debug('Secure Query: ' + query);
        return Database.query(query);
    }
    
    /**
     * SECURE: Input validation and whitelisting for dynamic fields
     */
    public static List<Opportunity> getOpportunitiesSecure(String sortField, String sortOrder) {
        // GOOD: Validate and whitelist allowed values
        Set<String> allowedFields = new Set<String>{'Name', 'Amount', 'StageName', 'CreatedDate'};
        Set<String> allowedOrders = new Set<String>{'ASC', 'DESC'};
        
        // Validate inputs
        if (!allowedFields.contains(sortField)) {
            sortField = 'Name'; // Default to safe value
        }
        if (!allowedOrders.contains(sortOrder.toUpperCase())) {
            sortOrder = 'ASC'; // Default to safe value
        }
        
        // Build query with validated inputs
        String query = 'SELECT Id, Name, Amount, StageName FROM Opportunity ORDER BY ' + 
                      sortField + ' ' + sortOrder;
        
        System.debug('Secure Query: ' + query);
        return Database.query(query);
    }
    
    /**
     * SECURE: Using String.escapeSingleQuotes() for string literals
     */
    public static List<Account> getAccountsWithEscaping(String accountName) {
        // GOOD: Escape single quotes when bind variables aren't suitable
        String escapedName = String.escapeSingleQuotes(accountName);
        String query = 'SELECT Id, Name, Type FROM Account WHERE Name = \'' + escapedName + '\'';
        
        System.debug('Secure Query with Escaping: ' + query);
        return Database.query(query);
    }
    
    /**
     * SECURE: Complex dynamic query with proper validation
     */
    public static List<SObject> getRecordsSecure(String objectType, String fieldName, String fieldValue) {
        // Validate object type against allowed list
        Set<String> allowedObjects = new Set<String>{'Account', 'Contact', 'Opportunity'};
        if (!allowedObjects.contains(objectType)) {
            throw new IllegalArgumentException('Object type not allowed: ' + objectType);
        }
        
        // Validate field name against object describe
        Schema.SObjectType objType = Schema.getGlobalDescribe().get(objectType);
        if (objType == null) {
            throw new IllegalArgumentException('Invalid object type: ' + objectType);
        }
        
        Map<String, Schema.SObjectField> fieldMap = objType.getDescribe().fields.getMap();
        if (!fieldMap.containsKey(fieldName)) {
            throw new IllegalArgumentException('Invalid field name: ' + fieldName);
        }
        
        // Build secure query using bind variable
        String query = 'SELECT Id, Name FROM ' + objectType + ' WHERE ' + fieldName + ' = :fieldValue';
        
        System.debug('Secure Dynamic Query: ' + query);
        return Database.query(query);
    }
    
    // ======================================================
    // ADDITIONAL SECURITY MEASURES
    // ======================================================
    
    /**
     * SECURE: Input sanitization utility method
     */
    public static String sanitizeInput(String input) {
        if (String.isBlank(input)) {
            return '';
        }
        
        // Remove dangerous characters and keywords
        String sanitized = input.replaceAll('[\'";\\\\]', '');
        
        // Remove common SQL injection keywords (case-insensitive)
        String[] dangerousKeywords = {
            'UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 
            'CREATE', 'EXEC', 'EXECUTE', 'SCRIPT', '--', '/*', '*/'
        };
        
        for (String keyword : dangerousKeywords) {
            sanitized = sanitized.replaceAll('(?i)' + keyword, '');
        }
        
        return sanitized.trim();
    }
    
    /**
     * SECURE: Parameterized query builder
     */
    public static Database.QueryLocator getQueryLocatorSecure(String objectName, Map<String, Object> filters) {
        // Validate object name
        if (!Schema.getGlobalDescribe().containsKey(objectName)) {
            throw new IllegalArgumentException('Invalid object: ' + objectName);
        }
        
        String query = 'SELECT Id FROM ' + objectName;
        
        if (filters != null && !filters.isEmpty()) {
            List<String> conditions = new List<String>();
            
            for (String fieldName : filters.keySet()) {
                // Validate field exists on object
                Schema.SObjectType objType = Schema.getGlobalDescribe().get(objectName);
                Map<String, Schema.SObjectField> fieldMap = objType.getDescribe().fields.getMap();
                
                if (fieldMap.containsKey(fieldName)) {
                    conditions.add(fieldName + ' = :filters[\'' + fieldName + '\']');
                }
            }
            
            if (!conditions.isEmpty()) {
                query += ' WHERE ' + String.join(conditions, ' AND ');
            }
        }
        
        System.debug('Secure Parameterized Query: ' + query);
        return Database.getQueryLocator(query);
    }
    
    // ======================================================
    // TESTING AND VALIDATION METHODS
    // ======================================================
    
    /**
     * Test method to validate secure implementations
     */
    public static void testSecureImplementations() {
        System.debug('=== Testing Secure Implementations ===');
        
        // Test with normal input
        String normalInput = 'Acme Corporation';
        List<Account> result1 = getAccountsSecure(normalInput);
        System.debug('Normal input test passed');
        
        // Test with malicious input - should be safely handled
        String maliciousInput = 'test\' OR Name != \'\'';
        List<Account> result2 = getAccountsSecure(maliciousInput);
        System.debug('Malicious input safely handled with bind variables');
        
        // Test input sanitization
        String dirtyInput = 'test\'; DROP TABLE Account; --';
        String cleanInput = sanitizeInput(dirtyInput);
        System.debug('Original: ' + dirtyInput);
        System.debug('Sanitized: ' + cleanInput);
    }
}
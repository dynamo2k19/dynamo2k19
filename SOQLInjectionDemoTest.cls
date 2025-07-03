/**
 * Test class for SOQL Injection demonstration
 * Shows how to test for security vulnerabilities and verify secure implementations
 */
@isTest
public class SOQLInjectionDemoTest {
    
    @testSetup
    static void setupTestData() {
        // Create test accounts
        List<Account> accounts = new List<Account>{
            new Account(Name = 'Test Account 1', Type = 'Customer'),
            new Account(Name = 'Test Account 2', Type = 'Partner'),
            new Account(Name = 'Acme Corporation', Type = 'Customer')
        };
        insert accounts;
        
        // Create test contacts
        List<Contact> contacts = new List<Contact>{
            new Contact(LastName = 'Smith', Department = 'Sales', Email = 'smith@test.com'),
            new Contact(LastName = 'Johnson', Department = 'Marketing', Email = 'johnson@test.com')
        };
        insert contacts;
        
        // Create test opportunities
        List<Opportunity> opportunities = new List<Opportunity>{
            new Opportunity(Name = 'Test Opp 1', StageName = 'Prospecting', CloseDate = Date.today().addDays(30), Amount = 10000),
            new Opportunity(Name = 'Test Opp 2', StageName = 'Closed Won', CloseDate = Date.today(), Amount = 15000)
        };
        insert opportunities;
    }
    
    // ======================================================
    // TESTS FOR SECURE IMPLEMENTATIONS
    // ======================================================
    
    @isTest
    static void testSecureAccountQuery() {
        Test.startTest();
        
        // Test normal input
        List<Account> normalResults = SOQLInjectionDemo.getAccountsSecure('Test Account 1');
        System.assertEquals(1, normalResults.size(), 'Should return exactly one account');
        System.assertEquals('Test Account 1', normalResults[0].Name, 'Should return correct account');
        
        // Test with special characters that would normally cause injection
        String maliciousInput = 'Test Account 1\' OR Name != \'\'';
        List<Account> injectionResults = SOQLInjectionDemo.getAccountsSecure(maliciousInput);
        System.assertEquals(0, injectionResults.size(), 'Should not return any accounts for malicious input');
        
        // Test with single quotes in legitimate input
        String legitimateInput = 'O\'Reilly Company';
        List<Account> quoteResults = SOQLInjectionDemo.getAccountsSecure(legitimateInput);
        System.assertEquals(0, quoteResults.size(), 'Should handle single quotes safely');
        
        Test.stopTest();
    }
    
    @isTest
    static void testSecureContactQuery() {
        Test.startTest();
        
        // Test normal input
        List<Contact> normalResults = SOQLInjectionDemo.getContactsSecure('Smith', 'Sales');
        System.assertEquals(1, normalResults.size(), 'Should return exactly one contact');
        
        // Test with injection attempt in multiple parameters
        String maliciousLastName = 'Smith\' OR LastName != \'\'';
        String maliciousDepartment = 'Sales\' OR Department != \'\'';
        List<Contact> injectionResults = SOQLInjectionDemo.getContactsSecure(maliciousLastName, maliciousDepartment);
        System.assertEquals(0, injectionResults.size(), 'Should not return any contacts for malicious input');
        
        Test.stopTest();
    }
    
    @isTest
    static void testSecureOpportunityQuery() {
        Test.startTest();
        
        // Test with valid field and order
        List<Opportunity> validResults = SOQLInjectionDemo.getOpportunitiesSecure('Name', 'ASC');
        System.assertEquals(2, validResults.size(), 'Should return all opportunities');
        
        // Test with invalid field (should default to 'Name')
        String maliciousField = 'Name; DROP TABLE Account; --';
        List<Opportunity> invalidFieldResults = SOQLInjectionDemo.getOpportunitiesSecure(maliciousField, 'ASC');
        System.assertEquals(2, invalidFieldResults.size(), 'Should still return results with default field');
        
        // Test with invalid sort order (should default to 'ASC')
        String maliciousOrder = 'ASC; SELECT * FROM User';
        List<Opportunity> invalidOrderResults = SOQLInjectionDemo.getOpportunitiesSecure('Amount', maliciousOrder);
        System.assertEquals(2, invalidOrderResults.size(), 'Should still return results with default order');
        
        Test.stopTest();
    }
    
    @isTest
    static void testAccountsWithEscaping() {
        Test.startTest();
        
        // Test normal input
        List<Account> normalResults = SOQLInjectionDemo.getAccountsWithEscaping('Test Account 1');
        System.assertEquals(1, normalResults.size(), 'Should return exactly one account');
        
        // Test with single quotes (should be escaped)
        String inputWithQuotes = 'Test\'s Account';
        List<Account> escapedResults = SOQLInjectionDemo.getAccountsWithEscaping(inputWithQuotes);
        System.assertEquals(0, escapedResults.size(), 'Should handle escaped quotes safely');
        
        Test.stopTest();
    }
    
    @isTest
    static void testSecureDynamicQuery() {
        Test.startTest();
        
        // Test valid object and field
        List<SObject> validResults = SOQLInjectionDemo.getRecordsSecure('Account', 'Name', 'Test Account 1');
        System.assertEquals(1, validResults.size(), 'Should return one account');
        
        // Test invalid object type
        try {
            SOQLInjectionDemo.getRecordsSecure('InvalidObject', 'Name', 'test');
            System.assert(false, 'Should throw exception for invalid object');
        } catch (IllegalArgumentException e) {
            System.assert(e.getMessage().contains('Object type not allowed'), 'Should throw appropriate error');
        }
        
        // Test invalid field name
        try {
            SOQLInjectionDemo.getRecordsSecure('Account', 'InvalidField', 'test');
            System.assert(false, 'Should throw exception for invalid field');
        } catch (IllegalArgumentException e) {
            System.assert(e.getMessage().contains('Invalid field name'), 'Should throw appropriate error');
        }
        
        Test.stopTest();
    }
    
    // ======================================================
    // SECURITY TESTING UTILITIES
    // ======================================================
    
    @isTest
    static void testInputSanitization() {
        Test.startTest();
        
        // Test dangerous characters removal
        String dirtyInput = 'test\'; DROP TABLE Account; --';
        String cleanInput = SOQLInjectionDemo.sanitizeInput(dirtyInput);
        System.assert(!cleanInput.contains('\''), 'Should remove single quotes');
        System.assert(!cleanInput.contains(';'), 'Should remove semicolons');
        System.assert(!cleanInput.contains('DROP'), 'Should remove dangerous keywords');
        
        // Test SQL injection keywords removal
        String sqlInjection = 'UNION SELECT password FROM User';
        String sanitizedSql = SOQLInjectionDemo.sanitizeInput(sqlInjection);
        System.assert(!sanitizedSql.contains('UNION'), 'Should remove UNION keyword');
        System.assert(!sanitizedSql.contains('SELECT'), 'Should remove SELECT keyword');
        
        // Test normal input is preserved
        String normalInput = 'Normal Company Name';
        String normalOutput = SOQLInjectionDemo.sanitizeInput(normalInput);
        System.assertEquals('Normal Company Name', normalOutput, 'Should preserve normal input');
        
        Test.stopTest();
    }
    
    @isTest
    static void testSecureQueryLocator() {
        Test.startTest();
        
        // Test valid object with filters
        Map<String, Object> filters = new Map<String, Object>{
            'Name' => 'Test Account 1'
        };
        Database.QueryLocator validLocator = SOQLInjectionDemo.getQueryLocatorSecure('Account', filters);
        System.assertNotEquals(null, validLocator, 'Should return valid query locator');
        
        // Test invalid object
        try {
            SOQLInjectionDemo.getQueryLocatorSecure('InvalidObject', filters);
            System.assert(false, 'Should throw exception for invalid object');
        } catch (IllegalArgumentException e) {
            System.assert(e.getMessage().contains('Invalid object'), 'Should throw appropriate error');
        }
        
        Test.stopTest();
    }
    
    // ======================================================
    // PENETRATION TESTING SCENARIOS
    // ======================================================
    
    @isTest
    static void testCommonInjectionPayloads() {
        Test.startTest();
        
        // Common SOQL injection payloads that should be safely handled
        String[] injectionPayloads = {
            '\' OR Name != \'\'',
            '\'; DELETE FROM Account WHERE Name != \'\'',
            '\' UNION SELECT Id, Name FROM User--',
            '\' AND 1=1--',
            '\' OR 1=1--',
            '/**/OR/**/1=1',
            '\' OR Name LIKE \'%\'',
            '\')) OR ((Name != \'\'',
            '\' OR (SELECT COUNT() FROM Account) > 0--'
        };
        
        for (String payload : injectionPayloads) {
            // Test that secure methods handle malicious payloads safely
            List<Account> results = SOQLInjectionDemo.getAccountsSecure(payload);
            System.assertEquals(0, results.size(), 'Payload should not return unauthorized data: ' + payload);
            
            // Test sanitization
            String sanitized = SOQLInjectionDemo.sanitizeInput(payload);
            System.assert(!sanitized.contains('\''), 'Should remove quotes from: ' + payload);
        }
        
        Test.stopTest();
    }
    
    @isTest
    static void testPerformanceOfSecureMethods() {
        Test.startTest();
        
        // Test that secure methods perform adequately
        Long startTime = System.currentTimeMillis();
        
        for (Integer i = 0; i < 10; i++) {
            SOQLInjectionDemo.getAccountsSecure('Test Account ' + i);
        }
        
        Long endTime = System.currentTimeMillis();
        Long duration = endTime - startTime;
        
        System.assert(duration < 5000, 'Secure methods should complete within reasonable time');
        
        Test.stopTest();
    }
    
    // ======================================================
    // INTEGRATION TESTS
    // ======================================================
    
    @isTest
    static void testFullWorkflowSecurity() {
        Test.startTest();
        
        // Simulate a complete user workflow with various inputs
        String[] userInputs = {
            'Test Account 1',           // Normal input
            'Acme Corporation',         // Another normal input
            'Test\' OR Name != \'\'',   // Injection attempt
            '',                         // Empty input
            null                        // Null input
        };
        
        for (String input : userInputs) {
            try {
                // Test each secure method with the input
                if (String.isNotBlank(input)) {
                    List<Account> accounts = SOQLInjectionDemo.getAccountsSecure(input);
                    
                    // Verify results are reasonable
                    System.assert(accounts.size() <= 3, 'Should not return excessive results for: ' + input);
                    
                    // Verify no injection occurred by checking if we got all accounts
                    if (input.contains('OR')) {
                        System.assertEquals(0, accounts.size(), 'Injection payload should return no results');
                    }
                }
            } catch (Exception e) {
                // Some inputs might cause legitimate exceptions - that's okay
                System.debug('Expected exception for input: ' + input + ' - ' + e.getMessage());
            }
        }
        
        Test.stopTest();
    }
    
    // ======================================================
    // COMPLIANCE AND AUDIT TESTS
    // ======================================================
    
    @isTest
    static void testSecurityCompliance() {
        Test.startTest();
        
        // Verify that all secure methods exist and are accessible
        System.assert(SOQLInjectionDemo.class.getDeclaredMethods().size() > 0, 'Demo class should have methods');
        
        // Test that demo methods can be called without throwing unexpected exceptions
        try {
            SOQLInjectionDemo.testSecureImplementations();
            SOQLInjectionDemo.demonstrateAttacks();
        } catch (Exception e) {
            System.debug('Demo methods executed with message: ' + e.getMessage());
        }
        
        Test.stopTest();
    }
    
    /**
     * Utility method to verify that a query doesn't contain injection artifacts
     */
    private static Boolean isQuerySecure(String query, String userInput) {
        // Check if user input appears unescaped in the query
        if (query.contains(userInput) && userInput.contains('\'')) {
            return false;
        }
        
        // Check for common injection patterns
        String[] injectionPatterns = {
            'OR.*!=.*', 'UNION.*SELECT', '--', '/\\*', '\\*/'
        };
        
        for (String pattern : injectionPatterns) {
            if (Pattern.matches('.*' + pattern + '.*', query)) {
                return false;
            }
        }
        
        return true;
    }
}
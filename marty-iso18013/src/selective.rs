//! Selective disclosure implementation
//!
//! Handles selective disclosure of mDL data elements based on user consent
//! and reader requests.

use crate::error::{Error, Result};
use std::collections::{HashMap, HashSet};

/// Selective disclosure manager
pub struct SelectiveDisclosure {
    /// Available data elements by namespace
    available: HashMap<String, HashSet<String>>,
    
    /// Mandatory elements that must always be disclosed
    mandatory: HashSet<String>,
}

impl SelectiveDisclosure {
    /// Create a new selective disclosure manager
    pub fn new() -> Self {
        Self {
            available: HashMap::new(),
            mandatory: HashSet::new(),
        }
    }

    /// Add available data elements for a namespace
    pub fn add_namespace(&mut self, namespace: String, elements: Vec<String>) {
        self.available.insert(namespace, elements.into_iter().collect());
    }

    /// Mark an element as mandatory
    pub fn add_mandatory(&mut self, element: String) {
        self.mandatory.insert(element);
    }

    /// Filter requested elements based on availability and user consent
    pub fn filter_request(
        &self,
        requested: &HashMap<String, Vec<String>>,
        user_approved: &HashMap<String, Vec<String>>,
    ) -> Result<HashMap<String, Vec<String>>> {
        let mut filtered = HashMap::new();
        
        for (namespace, elements) in requested {
            let available = self.available.get(namespace)
                .ok_or_else(|| Error::Other(format!("Namespace not available: {}", namespace)))?;
            
            let approved = user_approved.get(namespace)
                .map(|v| v.iter().cloned().collect::<HashSet<_>>())
                .unwrap_or_default();
            
            let mut namespace_elements = Vec::new();
            
            for element in elements {
                // Check if element is available
                if !available.contains(element) {
                    continue;
                }
                
                // Check if element is approved or mandatory
                if self.mandatory.contains(element) || approved.contains(element) {
                    namespace_elements.push(element.clone());
                }
            }

            // ISO 18013-5 §7.2.1: mandatory elements must always be included,
            // even if not explicitly requested by the reader.
            for mandatory_element in &self.mandatory {
                if available.contains(mandatory_element) && !namespace_elements.contains(mandatory_element) {
                    namespace_elements.push(mandatory_element.clone());
                }
            }
            
            if !namespace_elements.is_empty() {
                filtered.insert(namespace.clone(), namespace_elements);
            }
        }
        
        Ok(filtered)
    }
}

impl Default for SelectiveDisclosure {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selective_disclosure() {
        let mut sd = SelectiveDisclosure::new();
        
        // Add available elements
        sd.add_namespace(
            "org.iso.18013.5.1".to_string(),
            vec!["family_name".to_string(), "given_name".to_string(), "birth_date".to_string()],
        );
        
        // Mark family_name as mandatory
        sd.add_mandatory("family_name".to_string());
        
        // Request all three elements
        let mut requested = HashMap::new();
        requested.insert(
            "org.iso.18013.5.1".to_string(),
            vec!["family_name".to_string(), "given_name".to_string(), "birth_date".to_string()],
        );
        
        // User only approves given_name
        let mut approved = HashMap::new();
        approved.insert(
            "org.iso.18013.5.1".to_string(),
            vec!["given_name".to_string()],
        );
        
        let filtered = sd.filter_request(&requested, &approved).unwrap();
        
        // Should include mandatory family_name and approved given_name
        let elements = filtered.get("org.iso.18013.5.1").unwrap();
        assert_eq!(elements.len(), 2);
        assert!(elements.contains(&"family_name".to_string()));
        assert!(elements.contains(&"given_name".to_string()));
        assert!(!elements.contains(&"birth_date".to_string()));
    }
}

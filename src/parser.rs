use crate::Error;
use serde::{Deserialize, Deserializer};
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use std::collections::VecDeque;

#[derive(Debug)]
struct CustomYamlValue {
    value: YamlValue,
    tagged_paths: Vec<String>,
}

impl<'de> Deserialize<'de> for CustomYamlValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_custom_yaml(deserializer)
    }
}

fn deserialize_custom_yaml<'de, D>(deserializer: D) -> Result<CustomYamlValue, D::Error>
where
    D: Deserializer<'de>,
{
    let mut value = YamlValue::deserialize(deserializer)?;
    let mut path = VecDeque::new();
    let mut tagged_paths = Vec::new();
    collect_tagged_keys(&mut value, &mut path, &mut tagged_paths).map_err(|e| {
        serde::de::Error::custom(format!("Error parsing YAML at path {:?}: {:?}", path, e))
    })?;
    Ok(CustomYamlValue {
        value,
        tagged_paths,
    })
}

fn collect_tagged_keys(
    node: &mut YamlValue,
    path: &mut VecDeque<String>,
    paths: &mut Vec<String>,
) -> Result<(), Error> {
    match node {
        YamlValue::Mapping(map) => {
            for (key, value) in map {
                if let YamlValue::Tagged(tag) = &key {
                    let key_str = tag.as_ref().tag.to_string();
                    if key_str == "!sd" {
                        let new_val = tag
                            .as_ref()
                            .value
                            .as_str()
                            .ok_or(Error::YamlInvalidSDTag(key_str))?;
                        let full_path = build_full_path(path, new_val);
                        paths.push(full_path);
                    }
                } else if let YamlValue::String(key) = &key {
                    path.push_back(key.to_string());
                    collect_tagged_keys(value, path, paths)?;
                    path.pop_back();
                }
            }
        }
        YamlValue::Sequence(seq) => {
            for (index, value) in seq.iter_mut().enumerate() {
                path.push_back(index.to_string());
                collect_tagged_keys(value, path, paths)?;
                // Ugly hack to remove tag from sequence
                if let YamlValue::Tagged(tag) = &value {
                    let key_str = tag.as_ref().tag.to_string();
                    if key_str == "!sd" {
                        let new_val = tag
                            .as_ref()
                            .value
                            .as_str()
                            .ok_or(Error::YamlInvalidSDTag(key_str))?;
                        *value = YamlValue::String(new_val.to_string());
                    }
                }
                path.pop_back();
            }
        }
        YamlValue::Tagged(tag) => {
            let key_str = tag.as_ref().tag.to_string();
            if key_str == "!sd" {
                let mut full_path = String::new();
                for (index, path_fragment) in path.iter().enumerate() {
                    if index == 0 {
                        full_path = format!("/{}", path_fragment);
                    } else {
                        full_path = format!("{}/{}", full_path, path_fragment)
                    }
                }
                paths.push(full_path);
            }
        }
        _ => {}
    }

    Ok(())
}

fn build_full_path(path: &VecDeque<String>, additional_segment: &str) -> String {
    let full_path = path
        .iter()
        .fold(String::new(), |acc, frag| format!("{}/{}", acc, frag));
    format!("{}/{}", full_path, additional_segment)
}

/// Parses claims as a YAML string, converts it to JSON, and collects paths of elements tagged with `!sd`.
///
/// # Arguments
/// * `yaml_str` - A string slice that holds the YAML data.
///
/// # Returns
/// A `Result` containing a tuple of JSON value and a vector of tagged paths, or an error.
pub fn parse_yaml(yaml_str: &str) -> Result<(JsonValue, Vec<String>), Error> {
    let yaml_value: CustomYamlValue = serde_yaml::from_str(yaml_str)?;
    let json_str = serde_yaml::to_string(&yaml_value.value)?;
    let json: JsonValue = serde_yaml::from_str(&json_str)?;
    let tagged_paths = yaml_value.tagged_paths;
    Ok((json, tagged_paths))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_yaml1() {
        let yaml_str = r#"
            sub: user_42
            !sd given_name: John
            !sd family_name: Doe
            email: "johndoe@example.com"
            phone_number: "+1-202-555-0101"
            phone_number_verified: true
            address:
                !sd street_address: "123 Main St"
                !sd locality: Anytown
                region: Anystate
                country: US
            birthdate: "1940-01-01"
            updated_at: 1570000000
            !sd nationalities:
                - US
                - DE
            "#;

        let (json, tagged_paths) = parse_yaml(yaml_str).unwrap();
        println!("{:?}", json);
        println!("{:?}", tagged_paths);

        assert_eq!(
            json,
            serde_json::json!({
                "sub": "user_42",
                "given_name": "John",
                "family_name": "Doe",
                "email": "johndoe@example.com",
                "phone_number": "+1-202-555-0101",
                "phone_number_verified": true,
                "address": {
                    "street_address": "123 Main St",
                    "locality": "Anytown",
                    "region": "Anystate",
                    "country": "US"
                },
                "birthdate": "1940-01-01",
                "updated_at": 1570000000,
                "nationalities": [
                    "US",
                    "DE"
                ]
            })
        );

        assert_eq!(
            tagged_paths,
            vec![
                "/given_name",
                "/family_name",
                "/address/street_address",
                "/address/locality",
                "/nationalities",
            ]
        );
    }

    #[test]
    fn test_parse_yaml2() {
        let yaml_str = r#"
            sub: user_42
            !sd given_name: John
            !sd family_name: Doe
            email: "johndoe@example.com"
            phone_number: "+1-202-555-0101"
            phone_number_verified: true
            !sd address:
                street_address: "123 Main St"
                locality: Anytown
                region: Anystate
                country: US
            birthdate: "1940-01-01"
            updated_at: 1570000000
            nationalities:
                - !sd US
                - !sd DE
                - PL
            "#;

        let (json, tagged_paths) = parse_yaml(yaml_str).unwrap();
        println!("{:?}", json);
        println!("{:?}", tagged_paths);

        assert_eq!(
            json,
            serde_json::json!({
                "sub": "user_42",
                "given_name": "John",
                "family_name": "Doe",
                "email": "johndoe@example.com",
                "phone_number": "+1-202-555-0101",
                "phone_number_verified": true,
                "address": {
                    "street_address": "123 Main St",
                    "locality": "Anytown",
                    "region": "Anystate",
                    "country": "US"
                },
                "birthdate": "1940-01-01",
                "updated_at": 1570000000,
                "nationalities": [
                    "US",
                    "DE",
                    "PL"
                ]
            })
        );

        assert_eq!(
            tagged_paths,
            vec![
                "/given_name",
                "/family_name",
                "/address",
                "/nationalities/0",
                "/nationalities/1",
            ]
        );
    }
}

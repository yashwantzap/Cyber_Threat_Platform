import joblib
import pandas as pd
import google.generativeai as genai
import json
import os
from datetime import date
import sys

# Try to load from .env file first
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("Loaded environment from .env file")
except ImportError:
    print("python-dotenv not installed, using system environment variables")

# --- Configuration ---
MODEL_FILE = "threat_model.pkl"

# Get API key from environment variable for security
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if not GEMINI_API_KEY:
    print("Error: GEMINI_API_KEY environment variable not set.")
    print("Please set it using one of these methods:")
    print("  PowerShell: $env:GEMINI_API_KEY = 'your-api-key'")
    print("  Command Prompt: set GEMINI_API_KEY=your-api-key")
    print("  Or create a .env file with: GEMINI_API_KEY=your-api-key")
    
    # Ask user if they want to enter it manually for this session
    manual_key = input("\nEnter your Gemini API key manually (or press Enter to exit): ").strip()
    if manual_key:
        GEMINI_API_KEY = manual_key
    else:
        sys.exit(1)

# Configure Gemini AI
try:
    genai.configure(api_key=GEMINI_API_KEY)
    model_gemini = genai.GenerativeModel('gemini-1.5-flash-latest')
    print("Gemini AI configured successfully.")
except Exception as e:
    print(f"Error configuring Gemini AI: {e}")
    print("Please check your API key and internet connection.")
    sys.exit(1)

def load_trained_model(filename):
    """
    Loads a trained machine learning model from a file.
    
    Args:
        filename (str): Path to the model file
        
    Returns:
        model: Trained model object or None if loading fails
    """
    try:
        if not os.path.exists(filename):
            print(f"Error: Model file '{filename}' not found.")
            print("Please run the following commands first:")
            print("1. python data_collector.py")
            print("2. python threat_predictor.py")
            return None
        
        model = joblib.load(filename)
        print(f"Model loaded successfully from {filename}")
        return model
    except Exception as e:
        print(f"Error loading model from {filename}: {e}")
        return None

def generate_mitigation_plan(cve_id, risk_level, short_description, vendor_product=None):
    """
    Generates a human-readable mitigation plan using a generative AI model.
    
    Args:
        cve_id (str): CVE identifier
        risk_level (str): Predicted risk level
        short_description (str): Vulnerability description
        vendor_product (str): Vendor and product information
        
    Returns:
        str: Generated mitigation plan or error message
    """
    
    product_info = f"\nProduct: {vendor_product}" if vendor_product else ""
    
    prompt = f"""
You are a cybersecurity expert providing actionable advice for both technical and non-technical users.
The following vulnerability has been detected:

CVE ID: {cve_id}
Risk Level: {risk_level}{product_info}
Description: {short_description}

Create a comprehensive, step-by-step mitigation plan for this vulnerability. Use clear, understandable language. 
When technical terms are necessary, provide simple explanations.

Format your response as follows:

**🚨 THREAT SUMMARY:**
[Explain what this vulnerability means in simple terms - what could happen if exploited]

**⚡ IMMEDIATE ACTIONS (Do This Now):**
1. [Most critical action to take immediately]
2. [Second most critical action]
3. [Third immediate action]

**🔧 TECHNICAL REMEDIATION:**
1. [Specific technical steps for IT teams]
2. [Patching or update procedures]
3. [Configuration changes needed]

**🛡️ PROTECTIVE MEASURES:**
1. [Additional security controls to implement]
2. [Monitoring recommendations]
3. [Network segmentation or access controls]

**📋 VERIFICATION STEPS:**
1. [How to verify the vulnerability is mitigated]
2. [Testing procedures]
3. [Ongoing monitoring recommendations]

**⏰ TIMELINE:**
- Immediate (0-24 hours): [Actions]
- Short-term (1-7 days): [Actions]
- Long-term (ongoing): [Actions]

Keep the response practical, actionable, and prioritized by urgency.
"""

    print("\n🤖 Generating personalized mitigation plan...")
    try:
        response = model_gemini.generate_content(prompt)
        if response and hasattr(response, 'text') and response.text:
            return response.text
        else:
            return "⚠️ Unable to generate mitigation plan - empty response from AI service."
    except Exception as e:
        error_msg = f"⚠️ Unable to generate mitigation plan due to API error: {str(e)}"
        print(f"Gemini API Error: {e}")
        
        # Provide a basic fallback mitigation plan
        fallback_plan = f"""
**🚨 THREAT SUMMARY:**
A {risk_level.lower()} vulnerability ({cve_id}) has been identified that could potentially compromise system security.

**⚡ IMMEDIATE ACTIONS:**
1. Check if your systems use the affected product/service
2. Review and restrict network access to affected systems
3. Monitor systems for unusual activity

**🔧 TECHNICAL REMEDIATION:**
1. Check vendor websites for security patches or updates
2. Apply available security updates immediately
3. Consider temporary workarounds if patches aren't available

**🛡️ PROTECTIVE MEASURES:**
1. Implement network segmentation to isolate affected systems
2. Enable additional logging and monitoring
3. Review and update access controls

**📋 VERIFICATION STEPS:**
1. Confirm patches are successfully applied
2. Test system functionality after updates
3. Monitor for any signs of compromise

**⏰ TIMELINE:**
- Immediate: Assessment and isolation
- Short-term: Patching and remediation  
- Long-term: Monitoring and review

Note: This is a generic plan. Please consult with cybersecurity professionals for specific guidance.
"""
        return fallback_plan

def get_sample_vulnerabilities():
    """
    Returns a list of sample vulnerabilities for testing.
    
    Returns:
        list: List of sample vulnerability dictionaries
    """
    return [
        {
            'vulnerabilityName': 'Ivanti Connect Secure, Policy Secure, and ZTA Gateways Stack-Based Buffer Overflow Vulnerability',
            'shortDescription': 'Ivanti Connect Secure, Policy Secure, and ZTA Gateways contain a stack-based buffer overflow which can lead to unauthenticated remote code execution.',
            'cveID': 'CVE-2025-0282',
            'vendorProject': 'Ivanti',
            'product': 'Connect Secure, Policy Secure, and ZTA Gateways',
            'dateAdded': '2025-01-08',
            'requiredAction': 'Apply mitigations as set forth in the CISA instructions linked below to include conducting hunt activities, taking remediation actions if applicable, and applying updates prior to returning a device to service.'
        },
        {
            'vulnerabilityName': 'Apache HTTP Server Request Smuggling Vulnerability',
            'shortDescription': 'Apache HTTP Server versions contain a request smuggling vulnerability that allows attackers to bypass security controls.',
            'cveID': 'CVE-2024-DEMO',
            'vendorProject': 'Apache',
            'product': 'HTTP Server',
            'dateAdded': '2024-12-01',
            'requiredAction': 'Apply updates per vendor instructions and review configurations.'
        }
    ]

def preprocess_vulnerability_data(vulnerability_data):
    """
    Preprocesses vulnerability data for model prediction.
    
    Args:
        vulnerability_data (dict): Raw vulnerability data
        
    Returns:
        pandas.DataFrame: Preprocessed data ready for model prediction
    """
    try:
        # Create DataFrame
        df = pd.DataFrame([vulnerability_data])
        
        # Process date
        df['dateAdded'] = pd.to_datetime(df['dateAdded'])
        df['days_since_added'] = (pd.to_datetime(date.today()) - df['dateAdded']).dt.days

        # Handle missing values (must match training preprocessing)
        df['vulnerabilityName'] = df['vulnerabilityName'].fillna('Unknown')
        df['shortDescription'] = df['shortDescription'].fillna('No description')
        df['vendorProject'] = df['vendorProject'].fillna('Unknown')
        df['product'] = df['product'].fillna('Unknown')
        df['days_since_added'] = df['days_since_added'].fillna(0)

        return df
    except Exception as e:
        print(f"Error preprocessing vulnerability data: {e}")
        return None

def analyze_vulnerability(model, vulnerability_data):
    """
    Analyzes a vulnerability using the trained model.
    
    Args:
        model: Trained machine learning model
        vulnerability_data (dict): Vulnerability information
        
    Returns:
        tuple: (predicted_risk_level, confidence_score) or (None, None) if error
    """
    try:
        # Preprocess the data
        processed_df = preprocess_vulnerability_data(vulnerability_data)
        if processed_df is None:
            return None, None

        # Select features for prediction (must match training features)
        feature_columns = ['vulnerabilityName', 'shortDescription', 'vendorProject', 'product', 'days_since_added']
        features_for_prediction = processed_df[feature_columns]
        
        # Make prediction
        predicted_risk_level = model.predict(features_for_prediction)[0]
        
        # Try to get prediction probabilities for confidence score
        confidence_score = None
        try:
            if hasattr(model, 'predict_proba'):
                probabilities = model.predict_proba(features_for_prediction)[0]
                confidence_score = max(probabilities)
            elif hasattr(model.named_steps['classifier'], 'predict_proba'):
                probabilities = model.named_steps['classifier'].predict_proba(
                    model.named_steps['preprocessor'].transform(features_for_prediction)
                )[0]
                confidence_score = max(probabilities)
        except:
            confidence_score = None
            
        return predicted_risk_level, confidence_score
        
    except Exception as e:
        print(f"Error during vulnerability analysis: {e}")
        import traceback
        traceback.print_exc()
        return None, None

def display_analysis_results(vulnerability, risk_level, confidence_score, mitigation_plan):
    """
    Displays the analysis results in a formatted way.
    
    Args:
        vulnerability (dict): Vulnerability data
        risk_level (str): Predicted risk level
        confidence_score (float): Confidence in prediction
        mitigation_plan (str): Generated mitigation plan
    """
    print("\n" + "="*80)
    print("🔍 VULNERABILITY ANALYSIS RESULTS")
    print("="*80)
    
    print(f"📋 CVE ID: {vulnerability['cveID']}")
    print(f"🏢 Vendor: {vulnerability.get('vendorProject', 'Unknown')}")
    print(f"📦 Product: {vulnerability.get('product', 'Unknown')}")
    print(f"📅 Date Added: {vulnerability.get('dateAdded', 'Unknown')}")
    print(f"🎯 Predicted Risk Level: {risk_level}")
    
    if confidence_score:
        print(f"📊 Confidence Score: {confidence_score:.2%}")
    
    print(f"\n📝 Description:")
    print(f"   {vulnerability.get('shortDescription', 'No description available')}")
    
    if mitigation_plan:
        print("\n" + "="*80)
        print("🛡️ MITIGATION PLAN")
        print("="*80)
        print(mitigation_plan)
    
    print("\n" + "="*80)

def interactive_mode(model):
    """
    Runs an interactive mode where users can input vulnerability details.

    Args:
        model: Trained machine learning model
    """
    print("\n🎯 Interactive Vulnerability Analysis Mode")
    print("Enter vulnerability details (press Enter to skip optional fields):")

    try:
        cve_id = input("CVE ID: ").strip() or "CVE-UNKNOWN"
        vuln_name = input("Vulnerability Name: ").strip() or "Unknown Vulnerability"
        description = input("Short Description: ").strip() or "No description provided"
        vendor = input("Vendor/Project: ").strip() or "Unknown"
        product = input("Product: ").strip() or "Unknown"
        date_added = input("Date Added (YYYY-MM-DD) [default: today]: ").strip() or date.today().isoformat()

        # 💡 New line added to capture the requiredAction
        required_action = input("Required Action: ").strip() or "No required action specified"

        vulnerability = {
            'cveID': cve_id,
            'vulnerabilityName': vuln_name,
            'shortDescription': description,
            'vendorProject': vendor,
            'product': product,
            'dateAdded': date_added,
            'requiredAction': required_action
        }

        return vulnerability

    except KeyboardInterrupt:
        print("\n\nExiting interactive mode...")
        return None
    except Exception as e:
        print(f"Error in interactive mode: {e}")
        return None

def main():
    """
    Main function to run the threat analysis and mitigation generation.
    """
    print("🛡️ Cybersecurity Threat Analysis and Mitigation System")
    print("=" * 60)
    
    # Load the trained model
    model = load_trained_model(MODEL_FILE)
    if not model:
        print("\n❌ Cannot proceed without a trained model.")
        print("Please run the following commands first:")
        print("1. python data_collector.py")
        print("2. python threat_predictor.py")
        return

    print("✅ System ready for vulnerability analysis!")
    
    # Ask user for input mode
    print("\nChoose analysis mode:")
    print("1. Analyze sample vulnerabilities (recommended for testing)")
    print("2. Interactive mode (enter your own vulnerability)")
    
    try:
        choice = input("Enter your choice (1 or 2) [default: 1]: ").strip() or "1"
        
        if choice == "2":
            # Interactive mode
            vulnerability = interactive_mode(model)
            if not vulnerability:
                return
            vulnerabilities_to_analyze = [vulnerability]
        else:
            # Use sample vulnerabilities
            vulnerabilities_to_analyze = get_sample_vulnerabilities()
            print(f"\n📊 Analyzing {len(vulnerabilities_to_analyze)} sample vulnerabilities...")
    
        # Analyze each vulnerability
        for i, vulnerability in enumerate(vulnerabilities_to_analyze, 1):
            print(f"\n🔄 Processing vulnerability {i}/{len(vulnerabilities_to_analyze)}...")
            
            # Perform risk analysis
            risk_level, confidence_score = analyze_vulnerability(model, vulnerability)
            
            if risk_level is None:
                print(f"❌ Failed to analyze {vulnerability['cveID']}")
                continue
            
            print(f"✅ Risk Level Prediction: {risk_level}")
            
            # Generate mitigation plan
            vendor_product = f"{vulnerability.get('vendorProject', '')} {vulnerability.get('product', '')}".strip()
            mitigation_plan = generate_mitigation_plan(
                cve_id=vulnerability['cveID'],
                risk_level=risk_level,
                short_description=vulnerability['shortDescription'],
                vendor_product=vendor_product if vendor_product else None
            )
            
            # Display results
            display_analysis_results(vulnerability, risk_level, confidence_score, mitigation_plan)
            
            # Ask if user wants to continue (for multiple vulnerabilities)
            if i < len(vulnerabilities_to_analyze):
                continue_choice = input(f"\nPress Enter to analyze next vulnerability or 'q' to quit: ").strip().lower()
                if continue_choice == 'q':
                    break
        
        print("\n✅ Analysis completed successfully!")
        
    except KeyboardInterrupt:
        print("\n\n👋 Exiting system...")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
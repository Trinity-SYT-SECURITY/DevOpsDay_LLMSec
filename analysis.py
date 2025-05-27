import os
import re
import time
import streamlit as st
from openai import OpenAI
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold
from database import store_in_database, store_in_vector_db, get_db_connection
from utils import load_file_content
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize OLLAMA and Gemini clients
ollama_client = OpenAI(
    base_url='http://localhost:11434/v1',
    api_key='ollama'
)

# Load the Gemini API key from the .env file
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY not found in .env file")
genai.configure(api_key=GEMINI_API_KEY)
gemini_model = genai.GenerativeModel(model_name='gemini-2.0-flash')

OWASP_RISKS = {
    "CICD-SEC-1": "Insufficient traffic control mechanisms",
    "CICD-SEC-2": "Insufficient identity and access management",
    "CICD-SEC-3": "Dependency chain abuse",
    "CICD-SEC-4": "Pipeline poisoning execution (PPE)",
    "CICD-SEC-5": "Insufficient PBAC (Pipeline-Based Access Controls)",
    "CICD-SEC-6": "Poor credential hygiene",
    "CICD-SEC-7": "Insecure system configuration",
    "CICD-SEC-8": "Uncontrolled use of third-party services",
    "CICD-SEC-9": "Improper artifact integrity verification",
    "CICD-SEC-10": "Insufficient logging and visibility"
}

def analyze_with_ollama(content):
    prompt = f"""You are a DevSecOps security expert. Analyze the following CI/CD configuration file for potential security risks by considering the full context of the pipeline. Follow these steps:
    1. Thoroughly analyze the configuration file content to identify **specific** security risks. Do not assume risks exist unless there is clear evidence in the content.
    2. For each identified risk, explain the reason based on the specific content provided, not generic assumptions.
    3. Provide targeted remediation suggestions that are directly applicable to the identified risk.
    4. Assign a severity level (Low, Medium, High) based on the potential impact and likelihood of exploitation.
    5. If no security risks are found after careful analysis, explicitly state: "No vulnerabilities detected in the provided configuration."

    Configuration file content:
    {content[:3000]}

    Output format:
    ### Risk: [Risk Name]
    **Severity**: [Low/Medium/High]
    **Reason**: [Specific reason based on the content]
    **Suggestion**: [Targeted suggestion]
    
    If no risks are found:
    No vulnerabilities detected in the provided configuration.
    """
    try:
        response = ollama_client.chat.completions.create(
            model='jimscard/devopd:latest',
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Analysis failed: {str(e)}"

def analyze_with_gemini(content):
    prompt = f"""You are a DevSecOps security expert. Analyze the following project code for security issues by considering the full context of the code. Follow these steps:
    1. Thoroughly analyze the code content to identify **specific** security risks. Do not assume risks exist unless there is clear evidence in the content.
    2. For each identified risk, explain the reason based on the specific content provided, not generic assumptions.
    3. Provide targeted remediation suggestions that are directly applicable to the identified risk.
    4. Assign a severity level (Low, Medium, High) based on the potential impact and likelihood of exploitation.
    5. If no security risks are found after careful analysis, explicitly state: "No vulnerabilities detected in the provided code."

    Code content:
    {content}

    Output format:
    ### Risk: [Risk Name]
    **Severity**: [Low/Medium/High]
    **Reason**: [Specific reason based on the content]
    **Suggestion**: [Targeted suggestion]
    
    If no risks are found:
    No vulnerabilities detected in the provided code.
    """
    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = gemini_model.generate_content(
                prompt,
                safety_settings={
                    HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
                }
            )
            if response.candidates and response.candidates[0].content:
                return response.text
            else:
                return "No vulnerabilities detected in the provided code."
        except Exception as e:
            if "quota" in str(e).lower():
                if attempt < max_retries - 1:  # Don't sleep on the last attempt
                    st.warning(f"Gemini quota limit reached. Waiting 60 seconds before retrying... (Attempt {attempt + 1}/{max_retries})")
                    time.sleep(60)
                    continue
                else:
                    st.error(f"Gemini quota limit reached after {max_retries} attempts. Skipping this file.")
                    return f"Analysis failed due to quota limit: {str(e)}"
            else:
                return f"Analysis failed: {str(e)}"

def detect_owasp_risks(analysis_text, content):
    detected = []
    risk_blocks = re.split(r'### Risk:', analysis_text)[1:]
    for block in risk_blocks:
        risk_name_match = re.search(r'(.+?)\n', block)
        severity_match = re.search(r'\*\*Severity\*\*: (Low|Medium|High)', block)
        reason_match = re.search(r'\*\*Reason\*\*: (.+?)(?=\n\*\*Suggestion\*\*:|$)', block, re.DOTALL)
        
        if risk_name_match and severity_match and reason_match:
            risk_name = risk_name_match.group(1).strip()
            severity = severity_match.group(1)
            reason = reason_match.group(1).strip()

            if "registry" in risk_name.lower() and not re.search(r'registry|image', content, re.IGNORECASE):
                continue
            if "shell" in risk_name.lower() and not re.search(r'script|sh\b|bash|command', content, re.IGNORECASE):
                continue
            if "network" in risk_name.lower() and not re.search(r'network|host|bridge|overlay', content, re.IGNORECASE):
                continue
            if "gitlab" in risk_name.lower() and not re.search(r'gitlab|runner|token', content, re.IGNORECASE):
                continue

            detected.append({"risk_name": risk_name, "severity": severity})
    
    return detected

def scan_directory(directory, model_type):
    def clean_previous_data():
        with get_db_connection() as conn:
            conn.execute('DELETE FROM scan_results WHERE file_path LIKE ?', (f"{directory}%",))
            conn.commit()
    
    clean_previous_data()
    
    results = []
    risk_count = {}

    files = []
    for root, _, filenames in os.walk(directory):
        for file in filenames:
            file_path = os.path.join(root, file)
            files.append(file_path)  # Include all files, no filtering
    
    if not files:
        st.error(f"No files found in: {directory}")
        return [], {}

    progress_bar = st.progress(0)
    total_files = len(files)
    processed_files = 0  # Track the number of files actually processed
    
    for idx, file_path in enumerate(files):
        try:
            content = load_file_content(file_path)
            if not content:
                processed_files += 1  # Increment even if skipped
                progress_bar.progress(processed_files / total_files)
                continue

            st.write(f"Analyzing: {file_path}")
            
            analysis = analyze_with_ollama(content) if model_type == "OLLAMA" else analyze_with_gemini(content)
            
            if "Analysis failed" in analysis or "No vulnerabilities detected" in analysis:
                st.warning(f"Analysis may have failed for {file_path}")
                processed_files += 1  # Increment even if skipped
                progress_bar.progress(processed_files / total_files)
                continue

            detected_risks = detect_owasp_risks(analysis, content)
            for risk in detected_risks:
                risk_name = risk["risk_name"]
                severity = risk["severity"]
                if risk_name not in risk_count:
                    risk_count[risk_name] = {"Low": 0, "Medium": 0, "High": 0}
                risk_count[risk_name][severity] += 1

            store_in_database(file_path, content, detected_risks, analysis)
            store_in_vector_db(file_path, content, analysis, detect_owasp_risks)

            results.append({
                "file_path": file_path,
                "risks": detected_risks,
                "analysis": analysis
            })

            processed_files += 1
            progress_bar.progress(processed_files / total_files)
            time.sleep(1 if model_type == "OLLAMA" else 3)
            
        except Exception as e:
            st.error(f"Error processing {file_path}: {str(e)}")
            processed_files += 1  # Increment even if an error occurs
            progress_bar.progress(processed_files / total_files)
            continue

    # Ensure the progress bar reaches 100% at the end
    progress_bar.progress(1.0)
    st.success("Scan completed!")

    return results, risk_count

def generate_rag_response(question, context, model_type):
    try:
        if not context or not isinstance(context, list) or context[0] == ["no related files found"]:
            return "No related files found in the scan results."

        prompt = f"""You are a DevSecOps security expert. Answer the question strictly based on the provided context. Do not fabricate information if the context is insufficient.

        User question: {question}
        
        Relevant context:
        {context}

        The answer must include:
        1. Full file path
        2. Specific detected risks (using CICD-SEC numbers)
        3. Relevant code snippets
        4. Remediation suggestions

        If the context is empty, insufficient, or does not match the question, you must respond only with: No related files found in the scan results
        """
        if model_type == "OLLAMA":
            response = ollama_client.chat.completions.create(
                model='jimscard/devopd:latest',
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=1200
            )
            return response.choices[0].message.content
        else:
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    response = gemini_model.generate_content(
                        prompt,
                        safety_settings={
                            HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
                            HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
                            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
                        }
                    )
                    if response.candidates and response.candidates[0].content:
                        return response.text
                    else:
                        return "No response generated by Gemini. Please try again later."
                except Exception as e:
                    if "quota" in str(e).lower():
                        if attempt < max_retries - 1:
                            st.warning(f"Gemini quota limit reached in RAG response. Waiting 60 seconds before retrying... (Attempt {attempt + 1}/{max_retries})")
                            time.sleep(60)
                            continue
                        else:
                            st.error(f"Gemini quota limit reached after {max_retries} attempts in RAG response.")
                            return f"Response generation failed due to quota limit: {str(e)}"
                    else:
                        return f"Response generation failed: {str(e)}"
    except Exception as e:
        return f"Response generation failed: {str(e)}"
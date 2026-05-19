# AI Customer Service Assistant - Implementation Plan

## 1. Overview
The goal of this project is to develop an AI-powered customer service assistant. The assistant will handle user queries, leverage an internal database, perform external data searches, and utilize Retrieval-Augmented Generation (RAG) based on backend-provided documents. To ensure safety and compliance, the Lakera API will be integrated as a guardrail mechanism throughout the chat flow.

### 1.1 Technology Stack
*   **LLM Provider:** OpenRouter
*   **Model:** Claude 3 Opus
*   **Deployment:** Docker
*   **Guardrails:** Lakera API
*   **Core Capabilities:** Internal Database Access, External Data Queries, RAG (Retrieval-Augmented Generation)

## 2. System Architecture

### 2.1 Core Components
1.  **User Interface / API Gateway:** Receives user prompts and returns the final AI response.
2.  **Orchestrator (Backend Engine):** Manages the chat flow, tool execution (database, external search), RAG document retrieval, and LLM communication.
3.  **Lakera Guardrail Layer:** Intercepts data at multiple stages to detect prompt injection, PII leakage, toxicity, and hallucinations.
4.  **RAG Module:** Retrieves relevant context from backend documents.
5.  **LLM Integration:** Communicates with OpenRouter to utilize Claude Opus.

### 2.2 Docker Deployment Strategy
The application will be containerized using Docker to ensure consistency across environments.
*   **Dockerfile:** Defines the environment for the backend orchestrator (e.g., Python/Node.js).
*   **docker-compose.yml:** Orchestrates the core application container along with any necessary local services (like a local vector database for RAG or a caching layer).
*   **Environment Variables (`.env`):** Securely injects API keys for OpenRouter, Lakera, and internal database credentials.

## 3. Guardrail Implementation (Lakera API)
Security and compliance are critical for customer service. The Lakera API will be integrated at three specific checkpoints within the chat flow:

### Checkpoint 1: User Prompt Validation
*   **When:** Immediately after receiving the user's input.
*   **What is checked:** The raw user prompt.
*   **Purpose:** Detect and block prompt injections, jailbreak attempts, and inappropriate content before any processing occurs.

### Checkpoint 2: RAG Document Validation
*   **When:** After retrieving documents from the backend but before appending them to the LLM context.
*   **What is checked:** The text content of the retrieved RAG documents.
*   **Purpose:** Ensure the retrieved context does not contain sensitive internal PII, biased data, or corrupted/injected text from external sources.

### Checkpoint 3: LLM Output Validation
*   **When:** After receiving the response from Claude Opus via OpenRouter, but before sending it back to the user.
*   **What is checked:** The generated LLM response.
*   **Purpose:** Prevent hallucinations, ensure brand safety, block PII leakage, and verify the response aligns with customer service policies.

## 4. Chat Flow Execution Steps

1.  **Receive Input:** User submits a prompt.
2.  **Guardrail 1 (Input):** Send user prompt to Lakera API. If flagged, return a standard safety refusal message.
3.  **Information Retrieval & Routing:**
    *   Query the internal database if specific user/order data is required.
    *   Perform external data queries if necessary.
    *   Fetch relevant documents via backend RAG.
4.  **Guardrail 2 (RAG Context):** Send the retrieved RAG documents to Lakera API. If flagged, redact the sensitive parts or fallback to a general response.
5.  **Prompt Assembly:** Combine the safe user prompt, retrieved data, RAG context, and system instructions.
6.  **LLM Execution:** Send the assembled prompt to OpenRouter (Claude Opus).
7.  **Guardrail 3 (Output):** Send the LLM's response to Lakera API. If flagged, return a safe fallback message.
8.  **Final Response:** Deliver the validated response to the user.

## 5. Next Steps for Development
1.  Initialize the project repository and Docker configurations.
2.  Set up the OpenRouter API integration for Claude Opus.
3.  Develop the RAG retrieval pipeline and internal database connectors.
4.  Implement the Lakera API middleware at the three defined checkpoints.
5.  Test the chat flow with various edge cases and security testing prompts.

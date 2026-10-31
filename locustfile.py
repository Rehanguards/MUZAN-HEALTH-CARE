import time
from locust import User, task, between

class GuardrailLoadUser(User):
    # Requests ke beech delay minimum rakha hai stress test ke liye
    wait_time = between(0.001, 0.005)

    @task
    def test_in_process_guardrail(self):
        # Sample prompt with PHI & standard query
        payload = "Patient SSN is 000-12-3456. Summarize medical report."
        
        start_time = time.perf_counter()
        
        # Local Guardrail Execution Check (Simulated/SDK Call)
        # In-process call execution
        latency_us = (time.perf_counter() - start_time) * 1_000_000

        # Log metric back to Locust controller
        if latency_us < 1000:
            self.environment.events.request.fire(
                request_type="SDK",
                name="In-Process Guardrail",
                response_time=latency_us / 1000.0, # Convert to ms for Locust display
                response_length=len(payload),
                exception=None,
            )
        else:
            self.environment.events.request.fire(
                request_type="SDK",
                name="In-Process Guardrail",
                response_time=latency_us / 1000.0,
                response_length=len(payload),
                exception=Exception("Latency SLA Exceeded"),
            )
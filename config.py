from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    app_name: str = "SentinelMesh"
    app_env: str = "dev"
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Model artifacts
    model_path: str = "artifacts/anomaly_model.pkl"
    scaler_path: str = "artifacts/scaler.pkl"
    features_path: str = "artifacts/features.pkl"
    model_source_path: str = "artifacts/model_source.txt"

    # Detection thresholds
    anomaly_threshold: float = -0.35
    high_threshold: float = -0.50
    critical_threshold: float = -0.70

    # Firewall / blocking
    alert_cooldown_seconds: int = 45
    auto_block_enabled: bool = True
    block_on_severity: str = "CRITICAL,HIGH"
    block_duration_minutes: int = 60
    whitelist_ips: str = Field(default="127.0.0.1,::1,192.168.1.1")

    # Logging
    telemetry_log_path: str = "logs/telemetry.jsonl"
    incident_log_path: str = "logs/incidents.jsonl"
    firewall_log_path: str = "logs/firewall_blocks.log"
    report_dir: str = "reports"

    # Kaggle dataset (optional)
    kaggle_ids_dataset: str = ""

    # Telegram
    telegram_enabled: bool = False
    telegram_bot_token: str = ""
    telegram_chat_ids: str = ""          # comma-separated chat IDs

    # Email
    email_enabled: bool = False
    email_smtp_server: str = ""
    email_smtp_port: int = 587
    email_sender: str = ""
    email_password: str = ""
    email_recipients: str = ""

    # Twilio SMS (CRITICAL only)
    sms_enabled: bool = False
    twilio_sid: str = ""
    twilio_auth_token: str = ""
    twilio_from_number: str = ""
    twilio_to_numbers: str = ""

    # Live capture
    capture_interface: str = "WiFi"      # override with e.g. "Wi-Fi" on Windows
    capture_mode: str = "auto"           # auto | live | simulate

    @property
    def whitelist_ip_set(self) -> set:
        return {v.strip() for v in self.whitelist_ips.split(",") if v.strip()}

    @property
    def block_on_severity_set(self) -> set:
        return {v.strip().upper() for v in self.block_on_severity.split(",") if v.strip()}

    @property
    def telegram_chat_id_list(self) -> list:
        return [v.strip() for v in self.telegram_chat_ids.split(",") if v.strip()]

    @property
    def email_recipient_list(self) -> list:
        return [v.strip() for v in self.email_recipients.split(",") if v.strip()]

    @property
    def twilio_to_list(self) -> list:
        return [v.strip() for v in self.twilio_to_numbers.split(",") if v.strip()]


settings = Settings()

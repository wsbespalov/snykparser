import os
import peewee
from playhouse.postgres_ext import ArrayField
from datetime import datetime

from settings import SETTINGS

POSTGRES = SETTINGS.get("postgres", {})

pg_default_database = POSTGRES.get("database", "updater_db")
pg_default_user = POSTGRES.get("user", "admin")
pg_default_password = POSTGRES.get("password", "123")
pg_default_host = POSTGRES.get("host", "localhost")
pg_default_port = POSTGRES.get("port", "5432")

pg_drop_before = bool(POSTGRES.get("drop_pg_before", True))

pg_database = os.environ.get("PG_DATABASE", pg_default_database)
pg_user = os.environ.get("PG_USER", pg_default_user)
pg_password = os.environ.get("PG_PASS", pg_default_password)
pg_host = os.environ.get("PG_HOST", pg_default_host)
pg_port = os.environ.get("PG_PORT", pg_default_port)

database = peewee.PostgresqlDatabase(
    database=pg_database,
    user=pg_user,
    password=pg_password,
    host=pg_host,
    port=pg_port
)


class SNYK(peewee.Model):
    class Meta:
        database = database
        ordering = ("cve_id", )
        table_name = "vulnerabilities_snyk"
        
    id = peewee.PrimaryKeyField(null=False)
    type = peewee.TextField(default="", verbose_name="Vulnerability type")
    cve_id = peewee.TextField(default="", verbose_name="CVE ID")
    cve_url = peewee.TextField(default="", verbose_name="CVE URL")
    cwe_id = peewee.TextField(default="", verbose_name="CWE ID")
    cwe_url = peewee.TextField(default="", verbose_name="CWE URL")
    header_title = peewee.TextField(default="", verbose_name="Header Title")
    affecting_github = peewee.TextField(default="", verbose_name="Affecting Github")
    versions = peewee.TextField(default="", verbose_name="Versions")
    overview = peewee.TextField(default="", verbose_name="Overview")
    details = peewee.TextField(default="", verbose_name="Details")
    references = ArrayField(peewee.TextField, default=[], verbose_name="References", index=False)
    credit = peewee.TextField(default="", verbose_name="Cerdit")
    snyk_id = peewee.TextField(default="", verbose_name="Snyk DB ID")
    source_url = peewee.TextField(default="https://snyk.io")
    source = peewee.TextField(default="snyk", verbose_name="Vulnerability source")
    disclosed = peewee.DateTimeField(default=datetime.now, verbose_name="Disclosed time")
    published = peewee.DateTimeField(default=datetime.now, verbose_name="Published time")

    def __unicode__(self):
        return "snyk"

    def __str__(self):
        return str(self.snyk_id)

    @property
    def to_json(self):
        return dict(
            id=self.id,
            type=self.type,
            cve_id=self.cve_id,
            cve_url=self.cve_url,
            cwe_id=self.cwe_id,
            cwe_url=self.cwe_url,
            header_title=self.header_title,
            affecting_github=self.affecting_github,
            versions=self.versions,
            overview=self.overview,
            details=self.details,
            references=self.references,
            credit=self.credit,
            snyk_id=self.snyk_id,
            source=self.source,
            source_url=self.source_url,
            disclosed=self.disclosed,
            published=self.published
        )
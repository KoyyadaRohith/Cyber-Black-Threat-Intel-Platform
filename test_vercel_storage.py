import csv
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as app_module
import config as config_module
from config import Config
from services import threat_intel_cache


def make_history_row(source='manual'):
    return {
        'ip': '8.8.8.8',
        'date': '2026-10-04T12:30:00',
        'source': source,
        'country': 'United States',
        'isp': 'Google',
        'asn': 'AS15169',
        'risk_score': 5,
        'classification': 'Safe',
        'abuse_score': 0,
        'vt_detections': 0,
        'threat_summary': 'No significant threat indicators.',
        'duration_ms': 100,
        'sources_used': 'AbuseIPDB, VirusTotal, WHOIS',
        'actions_taken': 'Lookup Completed',
        'severity': 'Low',
        'tags': '',
        'notes': ''
    }


class VercelStorageExportTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        storage_dir = Path(self.temp_dir.name)

        Config.STORAGE_DIR = storage_dir
        Config.REPORTS_FOLDER = storage_dir / 'reports'
        Config.REPORTS_PDF = Config.REPORTS_FOLDER / 'pdf'
        Config.REPORTS_CSV = Config.REPORTS_FOLDER / 'csv'
        Config.REPORTS_TXT = Config.REPORTS_FOLDER / 'txt'
        Config.EXPORTS_FOLDER = storage_dir / 'exports'
        Config.GENERATED_REPORTS = Config.EXPORTS_FOLDER / 'generated_reports'
        Config.DOWNLOADED_FILES = Config.EXPORTS_FOLDER / 'downloaded_files'
        Config.UPLOAD_FOLDER = storage_dir / 'uploads'
        Config.UPLOAD_CSV = Config.UPLOAD_FOLDER / 'csv'
        Config.UPLOAD_TXT = Config.UPLOAD_FOLDER / 'txt'
        Config.UPLOAD_LOGS = Config.UPLOAD_FOLDER / 'logs'
        Config.UPLOAD_AVATARS = Config.UPLOAD_FOLDER / 'avatars'
        Config.DB_FOLDER = storage_dir / 'database'

        self.history = [
            make_history_row(),
            make_history_row('batch_test.csv_2026_10_04')
        ]
        self.client = app_module.app.test_client()
        app_module.app.config['TESTING'] = True

        for target, value in (
            (app_module.db, 'get_history'),
            (app_module.db, 'get_notifications')
        ):
            patcher = patch.object(
                target,
                value,
                return_value=self.history if value == 'get_history' else []
            )
            patcher.start()
            self.addCleanup(patcher.stop)

        notification_patcher = patch.object(app_module, 'add_notification')
        notification_patcher.start()
        self.addCleanup(notification_patcher.stop)

        with self.client.session_transaction() as session:
            session['username'] = 'test_analyst'

    def track_response(self, response):
        self.addCleanup(response.close)
        return response

    def test_history_and_reports_pages_render_without_filesystem_writes(self):
        history_response = self.client.get('/history')
        reports_response = self.client.get('/reports')

        self.assertEqual(history_response.status_code, 200)
        self.assertIn(b'window.print();', history_response.data)
        self.assertEqual(reports_response.status_code, 200)
        self.assertIn(b'Export PDF', reports_response.data)

    def test_history_csv_and_txt_downloads(self):
        csv_response = self.track_response(
            self.client.get('/reports/download/history_csv')
        )
        txt_response = self.track_response(
            self.client.get('/reports/download/history_txt')
        )

        self.assertEqual(csv_response.status_code, 200)
        self.assertEqual(csv_response.mimetype, 'text/csv')
        csv_rows = list(csv.DictReader(io.StringIO(csv_response.get_data(as_text=True))))
        self.assertEqual(len(csv_rows), len(self.history))
        self.assertEqual(csv_rows[0]['ip'], '8.8.8.8')

        self.assertEqual(txt_response.status_code, 200)
        self.assertEqual(txt_response.mimetype, 'text/plain')
        self.assertIn('HISTORY AUDIT', txt_response.get_data(as_text=True))

    def test_individual_and_bulk_print_exports(self):
        individual = self.track_response(
            self.client.get('/reports/download/individual_8.8.8.8')
        )
        bulk = self.track_response(
            self.client.get('/reports/download/bulk_batch_test.csv_2026_10_04')
        )

        self.assertEqual(individual.status_code, 200)
        self.assertEqual(individual.mimetype, 'text/html')
        self.assertIn(b'window.print();', individual.data)

        self.assertEqual(bulk.status_code, 200)
        self.assertEqual(bulk.mimetype, 'text/html')
        self.assertIn(b'window.print();', bulk.data)

    def test_bulk_csv_and_txt_downloads(self):
        csv_response = self.track_response(
            self.client.get('/reports/download/bulk_batch_test.csv_2026_10_04_csv')
        )
        txt_response = self.track_response(
            self.client.get('/reports/download/bulk_batch_test.csv_2026_10_04_txt')
        )

        self.assertEqual(csv_response.status_code, 200)
        self.assertEqual(csv_response.mimetype, 'text/csv')
        self.assertIn('8.8.8.8', csv_response.get_data(as_text=True))

        self.assertEqual(txt_response.status_code, 200)
        self.assertEqual(txt_response.mimetype, 'text/plain')
        self.assertIn('BATCH INGESTION SUMMARY', txt_response.get_data(as_text=True))

    def test_watchlist_exports_remain_downloadable(self):
        watchlist = [{
            'ip': '203.0.113.7',
            'risk_score': 70,
            'classification': 'Suspicious',
            'status': 'Active',
            'date_added': '2026-10-04T12:30:00'
        }]
        with patch.object(app_module.db, 'get_watchlist', return_value=watchlist):
            csv_response = self.track_response(
                self.client.get('/reports/download/watchlist_csv')
            )
            txt_response = self.track_response(
                self.client.get('/reports/download/watchlist_txt')
            )

        self.assertEqual(csv_response.status_code, 200)
        self.assertEqual(csv_response.mimetype, 'text/csv')
        self.assertIn('203.0.113.7', csv_response.get_data(as_text=True))
        self.assertEqual(txt_response.status_code, 200)
        self.assertEqual(txt_response.mimetype, 'text/plain')
        self.assertIn('WATCHLIST AUDIT', txt_response.get_data(as_text=True))

    def test_export_failure_is_logged_and_returns_http_500(self):
        with patch.object(
            app_module.report_gen,
            'generate_csv_report',
            side_effect=OSError('storage unavailable')
        ):
            response = self.client.get('/reports/download/history_csv')

        self.assertEqual(response.status_code, 500)
        self.assertIn('could not be generated', response.get_data(as_text=True))

    def test_threat_intel_cache_writes_under_runtime_storage(self):
        cache_file = Config.STORAGE_DIR / 'database' / 'threat_intel_cache.csv'
        with patch.object(threat_intel_cache, 'CACHE_FILE', cache_file):
            threat_intel_cache._write_csv_rows([])
            self.assertEqual(threat_intel_cache._read_csv_rows(), [])

        self.assertTrue(cache_file.is_relative_to(Config.STORAGE_DIR))
        self.assertTrue(cache_file.is_file())

    def test_vercel_folder_initialization_never_creates_deployment_paths(self):
        with (
            patch.object(config_module, 'IS_VERCEL', True),
            patch.object(Path, 'mkdir', autospec=True) as mkdir
        ):
            Config.init_folders()

        created_paths = [call.args[0] for call in mkdir.call_args_list]
        self.assertIn(Config.DB_FOLDER, created_paths)
        self.assertTrue(
            all(path.is_relative_to(Config.STORAGE_DIR) for path in created_paths)
        )
        self.assertTrue(
            all(not path.is_relative_to(Config.BASE_DIR) for path in created_paths)
        )

    def test_cache_write_failure_does_not_fail_intel_analysis(self):
        cache_file = Config.STORAGE_DIR / 'database' / 'missing' / 'cache.csv'
        with (
            patch.object(threat_intel_cache, 'CACHE_FILE', cache_file),
            patch.object(
                threat_intel_cache,
                '_write_csv_rows',
                side_effect=OSError('temporary storage unavailable')
            ),
            self.assertLogs('services.threat_intel_cache', level='ERROR')
        ):
            result = threat_intel_cache.get_cached_intel(
                '8.8.8.8',
                {'mock_mode': True}
            )

        self.assertEqual(result['ip'], '8.8.8.8')
        self.assertFalse(result['intel_meta']['cache_hit'])

    def test_file_upload_remains_in_memory_and_avatar_uses_runtime_storage(self):
        upload_response = self.client.post(
            '/file-upload',
            data={'file': (io.BytesIO(b'IP address: 203.0.113.7'), 'targets.txt')},
            content_type='multipart/form-data'
        )
        self.assertEqual(upload_response.status_code, 302)
        self.assertIn(
            '203.0.113.7',
            self.client.get('/analysis').get_data(as_text=True)
        )

        avatar_response = self.client.post(
            '/profile/upload-avatar',
            data={'avatar': (io.BytesIO(b'avatar-bytes'), 'avatar.png')},
            content_type='multipart/form-data'
        )
        self.assertEqual(avatar_response.status_code, 200)
        avatar_data = avatar_response.get_json()
        self.assertTrue(avatar_data['success'])
        self.assertTrue((Config.UPLOAD_AVATARS / 'test_analyst.png').is_file())

        served_avatar = self.client.get('/uploads/avatars/test_analyst.png')
        self.track_response(served_avatar)
        self.assertEqual(served_avatar.status_code, 200)
        self.assertEqual(served_avatar.data, b'avatar-bytes')


if __name__ == '__main__':
    unittest.main()

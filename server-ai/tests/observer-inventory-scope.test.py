import importlib.util
import pathlib
import unittest
from unittest.mock import patch

SOURCE = pathlib.Path(__file__).resolve().parents[2] / 'deployment/host/libexec/platform-docker-observer-proxy.py'
spec = importlib.util.spec_from_file_location('observer_scope', SOURCE)
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)


class ObserverScopeTests(unittest.TestCase):
    def test_only_explicitly_registered_names_are_visible(self):
        rows = [
            {'Id': 'a' * 64, 'Names': ['/core-database']},
            {'Id': 'b' * 64, 'Names': ['/unregistered-app']},
            {'Id': 'c' * 64, 'Names': ['/core-database', '/unregistered-alias']},
        ]
        with patch.object(proxy, 'registered_names', return_value=frozenset({'core-database'})):
            self.assertEqual(proxy.infrastructure_rows(rows), rows[:1])
            self.assertFalse(proxy.admitted_container(rows, 'b' * 64))
            with self.assertRaises(PermissionError):
                proxy.limited_inspect({'Name': '/unregistered-app'})

    def test_empty_inventory_exposes_no_containers(self):
        with patch.object(proxy, 'registered_names', return_value=frozenset()):
            self.assertEqual(proxy.infrastructure_rows([{'Id': 'a' * 64, 'Names': ['/core-database']}]), [])

    def test_missing_inventory_fails_closed(self):
        with patch.object(proxy, 'registered_names', side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                proxy.infrastructure_rows([{'Id': 'a' * 64, 'Names': ['/core-database']}])


if __name__ == '__main__':
    unittest.main()

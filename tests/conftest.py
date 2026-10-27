import pytest

from pcap_detective import synthetic as syn


@pytest.fixture(scope="session")
def demo_pcap(tmp_path_factory):
    path = tmp_path_factory.mktemp("caps") / "demo.pcap"
    syn.write_pcap(path, syn.demo_capture())
    return path


@pytest.fixture
def make_pcap(tmp_path):
    def make(packets, name="t.pcap"):
        path = tmp_path / name
        syn.write_pcap(path, packets)
        return str(path)

    return make

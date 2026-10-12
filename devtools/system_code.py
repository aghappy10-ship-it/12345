"""Finite source catalog and local-only drafts; never a camera deployment API."""
from __future__ import annotations

from dataclasses import dataclass
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import threading
import uuid

MAX_TEXT_BYTES = 32000
STOCK_ROOT = 'work/reverse/vendor/x2dii_1_3_16_2_system_root'

SECTIONS = (
    ('ui', '界面与菜单', '活动扩展 QML/UI 加载器、官方界面启动配置及有限历史分析。'),
    ('control', '拍摄控制', '拍摄服务启动配置、组件信息与有限控制路径反编译分析；不是完整原厂源码。'),
    ('hardware', '硬件采集与控制', '真实镜头数据格式；FBS 是 schema，不是驱动或硬件控制实现。'),
    ('imaging', '图像与算法', '真实 PDAF 数据格式与 AF 追踪查询；schema/SQL 不是算法实现。'),
    ('storage', '保存与持久化', '官方存储服务、卷管理配置和有限历史分析。'),
    ('platform', '基础系统', '平台启动配置与活动工程本地启动配置工具。'),
    ('maintenance', '通信与维护', 'USB/升级启动配置及活动工程清理/身份工具；草稿重置不是机身回滚。'),
)


@dataclass(frozen=True)
class Source:
    id: str
    section: str
    path: str
    kind: str
    owner: str = 'project'
    editable: bool = True
    device_path: str | None = None
    description: str = ''


# Explicit individual files only. No recursive vendor discovery or ELF decompile.
SOURCES = (
    Source('ui-page', 'ui', 'qml/X2d2MenuPage.qml', 'qml'),
    Source('ui-bootstrap', 'ui', 'qml/X2d2MenuBootstrap.qml', 'qml'),
    Source('ui-model', 'ui', 'qml/X2d2MenuModel.qml', 'qml'),
    Source('ui-stock-init', 'ui', STOCK_ROOT + '/etc/init/camera-gui.rc', 'init-rc', 'stock', True, '/system/etc/init/camera-gui.rc'),
    Source('ui-stock-analysis', 'ui', 'work/reverse/camera_gui_1_3_16_2_menu_feature_xrefs.json', 'decompiled-analysis', 'stock', False),
    Source('ui-camera-gui-binary', 'ui', STOCK_ROOT + '/bin/camera-gui', 'binary-metadata', 'stock', False, '/system/bin/camera-gui'),
    Source('ui-preload', 'ui', 'src/menu_preload.c', 'c', description='活动 UI 菜单加载器，不是拍摄控制 backend。'),
    Source('control-drive-analysis', 'control', 'work/reverse/camera_service_drive_mode_correct_decompile.txt', 'decompiled-analysis', 'stock', False),
    Source('maintenance-usb-init', 'maintenance', STOCK_ROOT + '/etc/init/init.eagle2.usb.rc', 'init-rc', 'stock', True, '/system/etc/init/init.eagle2.usb.rc'),
    Source('control-service-init', 'control', STOCK_ROOT + '/etc/init/camera-service.rc', 'init-rc', 'stock', True, '/system/etc/init/camera-service.rc'),
    Source('control-service-binary', 'control', STOCK_ROOT + '/bin/camera-service', 'binary-metadata', 'stock', False, '/system/bin/camera-service'),
    Source('hardware-lens-schema', 'hardware', STOCK_ROOT + '/etc/lensdb/lens.fbs', 'fbs-schema', 'stock', True, '/system/etc/lensdb/lens.fbs', '镜头数据 FlatBuffers schema，不是硬件控制实现。'),
    Source('hardware-stroke-schema', 'hardware', STOCK_ROOT + '/etc/lensdb/stroke.fbs', 'fbs-schema', 'stock', True, '/system/etc/lensdb/stroke.fbs', '镜头行程数据 schema，不是驱动实现。'),
    Source('hardware-sensor-config-info', 'hardware', STOCK_ROOT + '/etc/imx861bqr_hb722.conf', 'oversized-text-metadata', 'stock', False, '/system/etc/imx861bqr_hb722.conf', '大于 32000 字节的传感器配置，仅文件信息；未读取完整配置文本。'),
    Source('imaging-pdaf-schema', 'imaging', STOCK_ROOT + '/etc/lensdb/pdaf.fbs', 'fbs-schema', 'stock', True, '/system/etc/lensdb/pdaf.fbs', 'PDAF 数据格式 schema，不是算法实现。'),
    Source('imaging-af-trace-query', 'imaging', STOCK_ROOT + '/etc/trace_sql/af_libaf_run_dur.sql', 'sql', 'stock', True, '/system/etc/trace_sql/af_libaf_run_dur.sql', 'AF trace 耗时统计 SQL，不是 AF 算法实现。'),
    Source('storage-init', 'storage', STOCK_ROOT + '/etc/init/camera-storage.rc', 'init-rc', 'stock', True, '/system/etc/init/camera-storage.rc'),
    Source('storage-vold-init', 'storage', STOCK_ROOT + '/etc/init/vold.rc', 'init-rc', 'stock', True, '/system/etc/init/vold.rc'),
    Source('storage-analysis', 'storage', 'work/reverse/camera_service_storage_xrefs.json', 'decompiled-analysis', 'stock', False),
    Source('storage-service-binary', 'storage', STOCK_ROOT + '/bin/camera-storage', 'binary-metadata', 'stock', False, '/system/bin/camera-storage'),
    Source('platform-init', 'platform', STOCK_ROOT + '/etc/init/init.eagle2.rc', 'init-rc', 'stock', True, '/system/etc/init/init.eagle2.rc'),
    Source('platform-system-init', 'platform', STOCK_ROOT + '/etc/init/camera-system.rc', 'init-rc', 'stock', True, '/system/etc/init/camera-system.rc'),
    Source('platform-boot-tool', 'platform', 'tools/boot_config.py', 'python'),
    Source('platform-system-binary', 'platform', STOCK_ROOT + '/bin/camera-system', 'binary-metadata', 'stock', False, '/system/bin/camera-system'),
    Source('maintenance-upgrade-init', 'maintenance', STOCK_ROOT + '/etc/init/camera-upgrade.rc', 'init-rc', 'stock', True, '/system/etc/init/camera-upgrade.rc'),
    Source('maintenance-cleanup-tool', 'maintenance', 'tools/menu_owned_cleanup.py', 'python'),
    Source('maintenance-identity-tool', 'maintenance', 'tools/release_identity.py', 'python'),
    Source('maintenance-upgrade-binary', 'maintenance', STOCK_ROOT + '/bin/camera-upgrade', 'binary-metadata', 'stock', False, '/system/bin/camera-upgrade'),
)


class CodeError(ValueError):
    """Missing/unsafe/corrupt local input. No source or draft is overwritten."""


class CodeConflict(CodeError):
    """The caller's base hash or revision is no longer current."""


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _safe_path(root, relative=''):
    root = Path(os.path.abspath(root))
    path = Path(os.path.abspath(root / relative))
    try:
        path.relative_to(root)
    except ValueError as error:
        raise CodeError('Path escapes its fixed source/draft root') from error
    for component in (*reversed(path.parents), path):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise CodeError('Cannot validate path: ' + str(error)) from error
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise CodeError('Symbolic links, junctions and reparse points are not allowed')
    return path


def _read_bytes(path, limit=MAX_TEXT_BYTES):
    try:
        if not path.is_file():
            raise CodeError('Source or draft file is missing: ' + str(path))
        with path.open('rb') as stream:
            raw = stream.read(limit + 1)
    except OSError as error:
        raise CodeError('Cannot read local file: ' + str(error)) from error
    if len(raw) > limit:
        raise CodeError(f'Text exceeds the {limit}-byte UTF-8 limit; no truncation or editing permitted')
    return raw


def _decode(raw):
    if raw.startswith(b'\x7fELF') or b'\x00' in raw:
        raise CodeError('Binary content is not editable source text')
    try:
        return raw.decode('utf-8', errors='strict')
    except UnicodeError as error:
        raise CodeError('Source is not valid UTF-8 text') from error


class SystemCode:
    def __init__(self, project, data_root):
        self.project = Path(os.path.abspath(project))
        self.stock = self.project.parent / 'x2d2'
        self.drafts = Path(os.path.abspath(data_root)) / 'code-drafts'
        self.lock = threading.RLock()
        self.sources = {source.id: source for source in SOURCES}

    def _source(self, file_id):
        if type(file_id) is not str or file_id not in self.sources:
            raise CodeError('Unknown catalog file ID; paths are not accepted')
        return self.sources[file_id]

    def _descriptor(self, source):
        root = self.project if source.owner == 'project' else self.stock
        path = root / source.path
        result = {'id': source.id, 'name': path.name, 'section': source.section,
                  'kind': source.kind, 'description': source.description,
                  'editable': source.editable, 'available': False,
                  'deploymentQualified': False,
                  'provenance': {'scope': 'active-extension' if source.owner == 'project' else
                      'historical-analysis' if source.kind == 'decompiled-analysis' else 'frozen-stock-extraction',
                      'path': str(path), 'stockVersion': '1.3.16.2' if source.path.startswith(STOCK_ROOT + '/') else None,
                      'liveVerified': False, 'originalWritable': False}}
        result.update(sourceTag=result['provenance']['scope'], path=str(path), sourcePath=str(path))
        if source.device_path:
            result['devicePath'] = source.device_path
        return result

    def _original(self, source):
        root = self.project if source.owner == 'project' else self.stock
        path = _safe_path(root, source.path)
        if source.kind == 'oversized-text-metadata':
            try:
                info = path.stat()
                if not path.is_file():
                    raise CodeError('Configuration reference is not a regular file')
            except OSError as error:
                raise CodeError('Configuration reference is missing: ' + str(path)) from error
            text = json.dumps({'path': str(path), 'devicePath': source.device_path,
                'sizeBytes': info.st_size, 'maxEditableTextBytes': MAX_TEXT_BYTES,
                'fullTextRead': False, 'fullSourceSha256': None,
                'sourceRestored': False, 'note': 'File information only; complete configuration text is not included.'},
                ensure_ascii=False, indent=2)
            return text, _sha(text.encode('utf-8'))
        if source.kind == 'binary-metadata':
            try:
                info = path.stat()
                if not path.is_file():
                    raise CodeError('Compiled component is not a regular file')
                with path.open('rb') as stream:
                    header = stream.read(64)
            except OSError as error:
                raise CodeError('Compiled component is missing: ' + str(path)) from error
            text = json.dumps({'path': str(path), 'devicePath': source.device_path,
                'sizeBytes': info.st_size, 'format': 'ELF' if header.startswith(b'\x7fELF') else 'binary',
                'headerBytesRead': len(header), 'headerSha256': _sha(header),
                'fullBinarySha256': None, 'fullBinaryRead': False,
                'sourceRestored': False, 'note': 'Metadata only; compiled binary is not source code.'},
                ensure_ascii=False, indent=2)
            return text, _sha(text.encode('utf-8'))
        raw = _read_bytes(path)
        return _decode(raw), _sha(raw)

    def read(self, file_id):
        with self.lock:
            source = self._source(file_id)
            text, digest = self._original(source)
            original = text
            record = self._load_record(source) if source.editable else None
            if record is not None:
                metadata, text, original = record
                if digest != metadata['baseSha256']:
                    raise CodeConflict('Original source changed; the existing draft is preserved and editing/reset is blocked')
            result = self._descriptor(source)
            active = bool(record and metadata['active'])
            difference = ''.join(difflib.unified_diff(original.splitlines(keepends=True),
                text.splitlines(keepends=True), fromfile='original', tofile='local-draft')) if active else ''
            result.update(text=text, originalText=original, diff=difference,
                          sha256=_sha(text.encode('utf-8')), baseSha256=digest,
                          revision=metadata['revision'] if record else 0,
                          draft=active, available=True)
            result['provenance']['sourceSha256'] = digest if source.kind not in ('binary-metadata', 'oversized-text-metadata') else None
            if not source.editable:
                result['reason'] = '文件信息视图，不含完整配置文本，不可编辑。' if source.kind == 'oversized-text-metadata' else '只读二进制元数据或历史分析，不是可编辑原厂源码。'
            if source.kind == 'binary-metadata':
                result['sha256Scope'] = 'metadata-view-not-full-binary'
            elif source.kind == 'oversized-text-metadata':
                result['sha256Scope'] = 'metadata-view-not-source-content'
            return result

    def _record_path(self, source):
        return _safe_path(self.drafts, source.id + '/record.json')

    def _load_record(self, source):
        path = self._record_path(source)
        if not path.exists():
            if path.parent.exists() and any(path.parent.iterdir()):
                raise CodeError('Draft metadata is missing; existing copies are preserved')
            return None
        raw = _read_bytes(path, 4096)
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise CodeError('Duplicate key in draft metadata')
                result[key] = value
            return result
        try:
            metadata = json.loads(_decode(raw), object_pairs_hook=unique)
        except (ValueError, UnicodeError) as error:
            raise CodeError('Draft metadata is corrupt; it will not be overwritten') from error
        fields = {'schema', 'id', 'sourcePath', 'baseSha256', 'sha256', 'revision', 'active', 'textFile', 'baseFile'}
        if type(metadata) is not dict or set(metadata) != fields:
            raise CodeError('Draft metadata has invalid fields')
        revision = metadata['revision']
        if (metadata['schema'] != 1 or type(metadata['schema']) is not int or
                metadata['id'] != source.id or metadata['sourcePath'] != self._descriptor(source)['sourcePath'] or
                type(revision) is not int or not 1 <= revision < 2 ** 31 or type(metadata['active']) is not bool):
            raise CodeError('Draft identity/revision metadata is invalid')
        for name in ('baseSha256', 'sha256'):
            if type(metadata[name]) is not str or not re.fullmatch('[0-9a-f]{64}', metadata[name]):
                raise CodeError('Draft metadata hash is invalid')
        if (metadata['baseFile'] != 'base-' + metadata['baseSha256'] + '.txt' or
                type(metadata['textFile']) is not str or
                not re.fullmatch(r'rev-' + str(revision) + r'-[0-9a-f]{32}\.txt', metadata['textFile'])):
            raise CodeError('Draft metadata contains an unsafe copy path')
        base = _read_bytes(_safe_path(self.drafts, source.id + '/' + metadata['baseFile']))
        edited = _read_bytes(_safe_path(self.drafts, source.id + '/' + metadata['textFile']))
        if _sha(base) != metadata['baseSha256'] or _sha(edited) != metadata['sha256']:
            raise CodeError('Draft text/base copy hash mismatch; files are preserved')
        if not metadata['active'] and edited != base:
            raise CodeError('Reset draft does not match its original copy')
        return metadata, _decode(edited), _decode(base)

    def _record_token(self, source):
        path = self._record_path(source)
        return _sha(_read_bytes(path, 4096)) if path.exists() else None

    def _atomic(self, relative, raw):
        path = _safe_path(self.drafts, relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        _safe_path(self.drafts, relative)
        descriptor, temporary = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            _safe_path(self.drafts, relative)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _commit(self, source, text, base_sha256, revision, active):
        if not source.editable:
            raise CodeError('Binary metadata and historical analyses are read-only')
        current = self.read(source.id)
        if (type(base_sha256) is not str or base_sha256 != current['baseSha256'] or
                type(revision) is not int or revision != current['revision']):
            raise CodeConflict('Base SHA256 or draft revision is stale; nothing was overwritten')
        if type(text) is not str:
            raise CodeError('Draft content must be UTF-8 text')
        try:
            raw = text.encode('utf-8', errors='strict')
        except UnicodeError as error:
            raise CodeError('Draft content is not valid UTF-8') from error
        if len(raw) > MAX_TEXT_BYTES:
            raise CodeError(f'Draft exceeds the {MAX_TEXT_BYTES}-byte UTF-8 limit')
        _decode(raw)
        if revision + 1 >= 2 ** 31:
            raise CodeError('Draft revision limit reached')
        token = self._record_token(source)
        base_raw = current['originalText'].encode('utf-8')
        base_name = 'base-' + base_sha256 + '.txt'
        text_name = f'rev-{revision + 1}-{uuid.uuid4().hex}.txt'
        metadata = {'schema': 1, 'id': source.id, 'sourcePath': current['sourcePath'],
                    'baseSha256': base_sha256, 'sha256': _sha(raw), 'revision': revision + 1,
                    'active': active, 'textFile': text_name, 'baseFile': base_name}
        record_raw = json.dumps(metadata, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        if revision == 0:
            destination = _safe_path(self.drafts, source.id)
            if destination.exists():
                raise CodeError('Existing draft directory has no published record; it is preserved')
            # Publish the whole first generation, never a half-created draft slot.
            # A failed stage remains explicitly uncommitted and cannot mask a lost
            # or corrupt record in an already-published source.id directory.
            generation = '.uncommitted-' + source.id + '-' + uuid.uuid4().hex
            self._atomic(generation + '/' + base_name, base_raw)
            self._atomic(generation + '/' + text_name, raw)
            self._atomic(generation + '/record.json', record_raw)
            if self._original(source)[1] != base_sha256 or self._record_token(source) != token:
                raise CodeConflict('Source or draft metadata changed during first save; nothing was published')
            destination = _safe_path(self.drafts, source.id)
            if destination.exists():
                raise CodeConflict('Draft directory appeared during first save; nothing was overwritten')
            os.replace(_safe_path(self.drafts, generation), destination)
            return self.read(source.id)
        base_path = _safe_path(self.drafts, source.id + '/' + base_name)
        if base_path.exists():
            if _read_bytes(base_path) != base_raw:
                raise CodeError('Existing original copy is damaged; no overwrite permitted')
        else:
            self._atomic(source.id + '/' + base_name, base_raw)
        self._atomic(source.id + '/' + text_name, raw)
        if self._original(source)[1] != base_sha256 or self._record_token(source) != token:
            raise CodeConflict('Source or draft metadata changed during save; previous revision is preserved')
        self._atomic(source.id + '/record.json', record_raw)
        return self.read(source.id)

    def save(self, file_id, text, base_sha256, revision):
        with self.lock:
            return self._commit(self._source(file_id), text, base_sha256, revision, True)

    def reset(self, file_id, base_sha256, revision):
        """Reset this local draft only; never remove files or roll back a camera."""
        with self.lock:
            current = self.read(file_id)
            return self._commit(self._source(file_id), current['originalText'], base_sha256, revision, False)

    def catalog(self):
        with self.lock:
            sections = []
            for section_id, title, description in SECTIONS:
                files = []
                for source in SOURCES:
                    if source.section != section_id:
                        continue
                    descriptor = self._descriptor(source)
                    try:
                        document = self.read(source.id)
                        descriptor.update(available=True, editable=document['editable'],
                                          draft=document['draft'], revision=document['revision'])
                    except CodeError as error:
                        descriptor.update(editable=False, reason=str(error))
                    files.append(descriptor)
                sections.append({'id': section_id, 'title': title, 'description': description, 'files': files})
            return {'sections': sections, 'file_count': len(SOURCES), 'deploymentQualified': False,
                    'maxTextBytes': MAX_TEXT_BYTES, 'scope': 'finite-local-source-and-reference-catalog',
                    'notice': '有限清单，不代表已还原全部原厂源码；草稿不写工程或机身。'}

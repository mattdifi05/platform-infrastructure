// Pure metadata shared by the upload boundary and the isolated extractor.
// Keep SQL constraints in migration 012 aligned with this exact extension/MIME
// set; legacy PowerPoint (.ppt) is intentionally absent.
const DOCUMENT_TYPES = [
  [".pdf", "pdf", "application/pdf"],
  [".doc", "doc", "application/msword"],
  [".docx", "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
  [".docm", "docx", "application/vnd.ms-word.document.macroEnabled.12"],
  [".dotx", "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.template"],
  [".dotm", "docx", "application/vnd.ms-word.template.macroEnabled.12"],
  [".xls", "xls", "application/vnd.ms-excel"],
  [".xlsx", "xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
  [".xlsm", "xlsx", "application/vnd.ms-excel.sheet.macroEnabled.12"],
  [".xltx", "xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.template"],
  [".xltm", "xlsx", "application/vnd.ms-excel.template.macroEnabled.12"],
  [".pptx", "pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"],
  [".pptm", "pptx", "application/vnd.ms-powerpoint.presentation.macroEnabled.12"],
  [".potx", "pptx", "application/vnd.openxmlformats-officedocument.presentationml.template"],
  [".potm", "pptx", "application/vnd.ms-powerpoint.template.macroEnabled.12"],
  [".ppsx", "pptx", "application/vnd.openxmlformats-officedocument.presentationml.slideshow"],
  [".ppsm", "pptx", "application/vnd.ms-powerpoint.slideshow.macroEnabled.12"],
  [".odt", "odt", "application/vnd.oasis.opendocument.text"],
  [".ott", "odt", "application/vnd.oasis.opendocument.text-template"],
  [".ods", "ods", "application/vnd.oasis.opendocument.spreadsheet"],
  [".ots", "ods", "application/vnd.oasis.opendocument.spreadsheet-template"],
  [".odp", "odp", "application/vnd.oasis.opendocument.presentation"],
  [".otp", "odp", "application/vnd.oasis.opendocument.presentation-template"],
  [".rtf", "rtf", "application/rtf"],
  [".epub", "epub", "application/epub+zip"],
];

export const DOCUMENT_FORMATS = Object.freeze(Object.fromEntries(DOCUMENT_TYPES.map(([extension, format]) => [extension, format])));
// MIME tokens are case-insensitive on the wire; persist one lowercase spelling
// so multipart normalization, storage metadata, and PostgreSQL CHECKs agree.
export const DOCUMENT_MEDIA_TYPES = Object.freeze(Object.fromEntries(DOCUMENT_TYPES.map(([extension, , mediaType]) => [extension, mediaType.toLowerCase()])));
export const DOCUMENT_EXTENSIONS = Object.freeze(DOCUMENT_TYPES.map(([extension]) => extension));

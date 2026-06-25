import type { TranslationKey } from "../i18n";
import type { AvatarCrop, AvatarVisualFilter } from "../AvatarCropper";

type AvatarFilterSettings = {
  brightness: number;
  contrast: number;
  grayscale: number;
  saturation: number;
  sepia: number;
};

type AvatarFilterDefinition = {
  filter: AvatarFilterSettings;
  id: AvatarVisualFilter;
  textKey: TranslationKey;
  titleKey: TranslationKey;
};
export type AvatarImageSize = {
  height: number;
  width: number;
};
export type AvatarTranslate = (key: TranslationKey) => string;
export type DragHandle = "e" | "image" | "move" | "n" | "ne" | "nw" | "s" | "se" | "sw" | "w";
export type NormalizedAvatarCrop = AvatarCrop & {
  imageX: number;
  imageY: number;
  rotation: number;
};

export const avatarCanvasSize = 512;
export const avatarFilterDefinitions: ReadonlyArray<AvatarFilterDefinition> = [
  {
    filter: { brightness: 1, contrast: 1, grayscale: 0, saturation: 1, sepia: 0 },
    id: "natural",
    textKey: "ui.avatar.filter.natural.text",
    titleKey: "ui.avatar.filter.natural.title",
  },
  {
    filter: { brightness: 1.06, contrast: 0.96, grayscale: 0, saturation: 0.92, sepia: 0.04 },
    id: "soft",
    textKey: "ui.avatar.filter.soft.text",
    titleKey: "ui.avatar.filter.soft.title",
  },
  {
    filter: { brightness: 1.03, contrast: 1.08, grayscale: 0, saturation: 1.22, sepia: 0 },
    id: "cool",
    textKey: "ui.avatar.filter.cool.text",
    titleKey: "ui.avatar.filter.cool.title",
  },
  {
    filter: { brightness: 1.02, contrast: 1.04, grayscale: 0, saturation: 1.06, sepia: 0.24 },
    id: "warm",
    textKey: "ui.avatar.filter.warm.text",
    titleKey: "ui.avatar.filter.warm.title",
  },
  {
    filter: { brightness: 1.02, contrast: 1.12, grayscale: 1, saturation: 0, sepia: 0 },
    id: "mono",
    textKey: "ui.avatar.filter.mono.text",
    titleKey: "ui.avatar.filter.mono.title",
  },
];
const minCropSize = 0.24;
export const cropHandles: readonly DragHandle[] = ["nw", "n", "ne", "e", "se", "s", "sw", "w"];

export function getAvatarImageFit(imageSize: AvatarImageSize | null) {
  if (!imageSize || imageSize.height <= 0 || imageSize.width <= 0) {
    return { overflowX: 0, overflowY: 0 };
  }

  if (imageSize.width > imageSize.height) {
    return { overflowX: (imageSize.width / imageSize.height) - 1, overflowY: 0 };
  }

  if (imageSize.height > imageSize.width) {
    return { overflowX: 0, overflowY: (imageSize.height / imageSize.width) - 1 };
  }

  return { overflowX: 0, overflowY: 0 };
}

export function cropFromHandle(crop: AvatarCrop, handle: DragHandle, pointX: number, pointY: number): AvatarCrop {
  const right = crop.x + crop.size;
  const bottom = crop.y + crop.size;
  const centerX = crop.x + (crop.size / 2);
  const centerY = crop.y + (crop.size / 2);
  let nextSize = crop.size;
  let nextX = crop.x;
  let nextY = crop.y;

  if (handle === "e") {
    nextSize = pointX - crop.x;
    nextY = centerY - (nextSize / 2);
  }
  if (handle === "w") {
    nextSize = right - pointX;
    nextX = right - nextSize;
    nextY = centerY - (nextSize / 2);
  }
  if (handle === "s") {
    nextSize = pointY - crop.y;
    nextX = centerX - (nextSize / 2);
  }
  if (handle === "n") {
    nextSize = bottom - pointY;
    nextX = centerX - (nextSize / 2);
    nextY = bottom - nextSize;
  }

  if (handle === "se") nextSize = Math.max(pointX - crop.x, pointY - crop.y);
  if (handle === "sw") {
    nextSize = Math.max(right - pointX, pointY - crop.y);
    nextX = right - nextSize;
  }
  if (handle === "ne") {
    nextSize = Math.max(pointX - crop.x, bottom - pointY);
    nextY = bottom - nextSize;
  }
  if (handle === "nw") {
    nextSize = Math.max(right - pointX, bottom - pointY);
    nextX = right - nextSize;
    nextY = bottom - nextSize;
  }

  return normalizeAvatarCrop({ ...crop, size: nextSize, x: nextX, y: nextY });
}

export function avatarFilterToCss(filterId: AvatarVisualFilter) {
  const filter = avatarFilterDefinitions.find((definition) => definition.id === filterId)?.filter ?? avatarFilterDefinitions[0]!.filter;
  return [
    `brightness(${filter.brightness})`,
    `contrast(${filter.contrast})`,
    `saturate(${filter.saturation})`,
    filter.grayscale ? `grayscale(${filter.grayscale})` : "",
    filter.sepia ? `sepia(${filter.sepia})` : "",
  ].filter(Boolean).join(" ");
}

export function getAvatarFallbackInitials(name: string | undefined, fallback: string) {
  const source = (name?.trim() || fallback.trim() || "ST").trim();
  const words = source.match(/[\p{L}\p{N}]+/gu) ?? [];
  if (words.length === 0) return "ST";
  if (words.length === 1) return words[0]!.slice(0, 2).toLocaleUpperCase();

  const first = words[0]!;
  const last = words[words.length - 1]!;
  if (first.toLocaleLowerCase() === last.toLocaleLowerCase() && first.length <= 2) {
    return first.toLocaleUpperCase();
  }

  return `${first.slice(0, 1)}${last.slice(0, 1)}`.toLocaleUpperCase();
}

export function normalizeAvatarCrop(crop: AvatarCrop): NormalizedAvatarCrop {
  const size = clamp(crop.size, minCropSize, 1);
  return {
    imageX: clamp(crop.imageX ?? 0.5, 0, 1),
    imageY: clamp(crop.imageY ?? 0.5, 0, 1),
    rotation: normalizeAvatarRotation(crop.rotation),
    size,
    x: clamp(crop.x, 0, 1 - size),
    y: clamp(crop.y, 0, 1 - size),
  };
}

function normalizeAvatarRotation(rotation: number | undefined) {
  if (typeof rotation !== "number" || !Number.isFinite(rotation)) return 0;
  return ((rotation % 360) + 360) % 360;
}

export function rotateAvatarCanvas(sourceCanvas: HTMLCanvasElement, rotation: number) {
  const normalizedRotation = normalizeAvatarRotation(rotation);
  if (normalizedRotation === 0) return sourceCanvas;

  const canvas = document.createElement("canvas");
  canvas.width = sourceCanvas.width;
  canvas.height = sourceCanvas.height;
  const context = canvas.getContext("2d");
  if (!context) throw new Error("avatar_canvas_unavailable");

  context.translate(canvas.width / 2, canvas.height / 2);
  context.rotate((normalizedRotation * Math.PI) / 180);
  context.drawImage(sourceCanvas, -sourceCanvas.width / 2, -sourceCanvas.height / 2);
  return canvas;
}

export function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

export function loadAvatarImage(source: string) {
  return new Promise<HTMLImageElement>((resolve, reject) => {
    const image = new Image();
    image.addEventListener("load", () => resolve(image));
    image.addEventListener("error", () => reject(new Error("avatar_image_unavailable")));
    if (!source.startsWith("data:")) image.crossOrigin = "anonymous";
    image.src = source;
  });
}

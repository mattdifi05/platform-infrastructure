"use client";

import { useEffect, useId, useMemo, useRef, useState, type PointerEvent, type ReactNode } from "react";
import { Button } from "./Button";
import { classNames } from "./classNames";
import { ChevronLeft, ChevronRight, Sliders } from "./icons";
import { cssEscape } from "./cssom";
import { useDynamicCssProperties } from "./styleMotion";
import {
  avatarCanvasSize,
  avatarFilterDefinitions,
  avatarFilterToCss,
  clamp,
  cropFromHandle,
  cropHandles,
  getAvatarFallbackInitials,
  getAvatarImageFit,
  loadAvatarImage,
  normalizeAvatarCrop,
  rotateAvatarCanvas,
  type AvatarImageSize,
  type AvatarTranslate,
  type DragHandle,
  type NormalizedAvatarCrop,
} from "./avatar-cropper/AvatarCropperModel";

export type AvatarCrop = {
  imageX?: number;
  imageY?: number;
  rotation?: number;
  size: number;
  x: number;
  y: number;
};

export type AvatarVisualFilter = "cool" | "mono" | "natural" | "soft" | "warm";

type AvatarCropperProps = {
  actions?: ReactNode;
  crop: AvatarCrop;
  cropLabel?: string;
  filterId?: AvatarVisualFilter;
  filterControls?: ReactNode;
  initials: string;
  name?: string;
  onCropChange: (crop: AvatarCrop) => void;
  previewFooter?: ReactNode;
  source: string | null;
};

export type AvatarVisualFilterItem = {
  id: AvatarVisualFilter;
  text: string;
  title: string;
};

type AvatarFilterStepperProps = {
  className?: string;
  filters: ReadonlyArray<AvatarVisualFilterItem>;
  nextLabel: string;
  onChange: (filterId: AvatarVisualFilter) => void;
  previousLabel: string;
  value: AvatarVisualFilter;
};

type DragState = {
  crop: NormalizedAvatarCrop;
  handle: DragHandle;
  startX: number;
  startY: number;
};

const avatarCropDynamicProperties = [
  "--ui-avatar-crop-size",
  "--ui-avatar-crop-x",
  "--ui-avatar-crop-y",
] as const;
const avatarMediaDynamicProperties = [
  "--ui-avatar-object-x",
  "--ui-avatar-object-y",
  "--ui-avatar-rotation",
] as const;

export function getAvatarVisualFilterItems(t: AvatarTranslate) {
  return avatarFilterDefinitions.map(({ id, textKey, titleKey }) => ({
    id,
    text: t(textKey),
    title: t(titleKey),
  }));
}

export function AvatarFilterStepper({
  className,
  filters,
  nextLabel,
  onChange,
  previousLabel,
  value,
}: AvatarFilterStepperProps) {
  const selectedIndex = Math.max(0, filters.findIndex((filter) => filter.id === value));
  const selectedFilter = filters[selectedIndex] ?? filters[0];
  const hasMultipleFilters = filters.length > 1;

  function moveFilter(direction: -1 | 1) {
    if (!hasMultipleFilters) return;

    const nextIndex = (selectedIndex + direction + filters.length) % filters.length;
    const nextFilter = filters[nextIndex];
    if (nextFilter) onChange(nextFilter.id);
  }

  if (!selectedFilter) return null;

  return (
    <div className={classNames("ui-avatar-filter-controls", className)} role="group" aria-label={selectedFilter.title}>
      <Button
        aria-label={previousLabel}
        className="ui-round-icon ui-avatar-filter-arrow"
        compact
        disabled={!hasMultipleFilters}
        icon={ChevronLeft}
        iconSize={15}
        onClick={() => moveFilter(-1)}
        variant="muted"
      />
      <span className="ui-avatar-filter-current" key={selectedFilter.id}>
        <Sliders aria-hidden="true" size={14} />
        <strong>{selectedFilter.title}</strong>
      </span>
      <Button
        aria-label={nextLabel}
        className="ui-round-icon ui-avatar-filter-arrow"
        compact
        disabled={!hasMultipleFilters}
        icon={ChevronRight}
        iconSize={15}
        onClick={() => moveFilter(1)}
        variant="muted"
      />
    </div>
  );
}

export function renderAvatarImage(source: string, filterId: AvatarVisualFilter, crop: AvatarCrop) {
  return loadAvatarImage(source).then((image) => {
    const canvas = document.createElement("canvas");
    canvas.width = avatarCanvasSize;
    canvas.height = avatarCanvasSize;
    const context = canvas.getContext("2d");
    if (!context) throw new Error("avatar_canvas_unavailable");

    const naturalWidth = image.naturalWidth || image.width;
    const naturalHeight = image.naturalHeight || image.height;
    const normalizedCrop = normalizeAvatarCrop(crop);
    const visibleSourceSize = Math.min(naturalWidth, naturalHeight);
    const sourceOriginX = Math.max(0, naturalWidth - visibleSourceSize) * normalizedCrop.imageX;
    const sourceOriginY = Math.max(0, naturalHeight - visibleSourceSize) * normalizedCrop.imageY;
    const sourceSize = visibleSourceSize * normalizedCrop.size;
    const sx = sourceOriginX + (normalizedCrop.x * visibleSourceSize);
    const sy = sourceOriginY + (normalizedCrop.y * visibleSourceSize);
    context.filter = avatarFilterToCss(filterId);
    context.drawImage(image, sx, sy, sourceSize, sourceSize, 0, 0, avatarCanvasSize, avatarCanvasSize);
    const outputCanvas = rotateAvatarCanvas(canvas, normalizedCrop.rotation);
    return outputCanvas.toDataURL("image/jpeg", 0.9);
  });
}

export function AvatarCropper({
  actions,
  crop,
  cropLabel = "Crop photo",
  filterId = "natural",
  filterControls,
  initials,
  name,
  onCropChange,
  previewFooter,
  source,
}: AvatarCropperProps) {
  const cropperId = useId().replace(/:/g, "");
  const frameRef = useRef<HTMLDivElement | null>(null);
  const dragRef = useRef<DragState | null>(null);
  const [imageSize, setImageSize] = useState<AvatarImageSize | null>(null);
  const normalizedCrop = normalizeAvatarCrop(crop);
  const imageFit = useMemo(() => getAvatarImageFit(imageSize), [imageSize]);
  const photoDraggable = Boolean(source && normalizedCrop.size >= 0.995 && (imageFit.overflowX > 0 || imageFit.overflowY > 0));
  const fallbackInitials = getAvatarFallbackInitials(name, initials);
  const fallbackLabel = (name?.trim() || fallbackInitials).trim();
  useDynamicCssProperties(
    `.ui-avatar-crop-box[data-ui-avatar-crop-id="${cssEscape(cropperId)}"]`,
    {
    "--ui-avatar-crop-size": `${normalizedCrop.size * 100}%`,
    "--ui-avatar-crop-x": `${normalizedCrop.x * 100}%`,
    "--ui-avatar-crop-y": `${normalizedCrop.y * 100}%`,
    },
    avatarCropDynamicProperties,
  );
  useDynamicCssProperties(
    `.ui-avatar-media[data-ui-avatar-media-id="${cssEscape(cropperId)}"]`,
    {
    "--ui-avatar-object-x": `${(imageFit.overflowX > 0 ? normalizedCrop.imageX : 0.5) * 100}%`,
    "--ui-avatar-object-y": `${(imageFit.overflowY > 0 ? normalizedCrop.imageY : 0.5) * 100}%`,
    "--ui-avatar-rotation": `${normalizedCrop.rotation}deg`,
    },
    avatarMediaDynamicProperties,
  );

  useEffect(() => {
    let cancelled = false;
    if (!source) {
      setImageSize(null);
      return () => {
        cancelled = true;
      };
    }

    void loadAvatarImage(source).then((image) => {
      if (cancelled) return;
      setImageSize({
        height: image.naturalHeight || image.height,
        width: image.naturalWidth || image.width,
      });
    }).catch(() => {
      if (!cancelled) setImageSize(null);
    });

    return () => {
      cancelled = true;
    };
  }, [source]);

  function pointFromEvent(event: PointerEvent<HTMLElement>) {
    const frame = frameRef.current;
    if (!frame) return null;
    const bounds = frame.getBoundingClientRect();
    const side = Math.max(1, Math.min(bounds.width, bounds.height));
    return {
      x: clamp((event.clientX - bounds.left) / side, 0, 1),
      y: clamp((event.clientY - bounds.top) / side, 0, 1),
    };
  }

  function startDrag(handle: DragHandle, event: PointerEvent<HTMLElement>) {
    if (!source) return;
    const point = pointFromEvent(event);
    if (!point) return;
    event.preventDefault();
    event.currentTarget.setPointerCapture(event.pointerId);
    const resolvedHandle = handle === "move" && photoDraggable ? "image" : handle;
    dragRef.current = {
      crop: normalizedCrop,
      handle: resolvedHandle,
      startX: point.x,
      startY: point.y,
    };
  }

  function moveDrag(event: PointerEvent<HTMLElement>) {
    const drag = dragRef.current;
    if (!drag) return;
    const point = pointFromEvent(event);
    if (!point) return;
    event.preventDefault();

    if (drag.handle === "image") {
      onCropChange(normalizeAvatarCrop({
        ...drag.crop,
        imageX: imageFit.overflowX > 0 ? drag.crop.imageX - ((point.x - drag.startX) / imageFit.overflowX) : drag.crop.imageX,
        imageY: imageFit.overflowY > 0 ? drag.crop.imageY - ((point.y - drag.startY) / imageFit.overflowY) : drag.crop.imageY,
      }));
      return;
    }

    if (drag.handle === "move") {
      onCropChange(normalizeAvatarCrop({
        ...drag.crop,
        x: drag.crop.x + point.x - drag.startX,
        y: drag.crop.y + point.y - drag.startY,
      }));
      return;
    }

    onCropChange(cropFromHandle(drag.crop, drag.handle, point.x, point.y));
  }

  function stopDrag(event: PointerEvent<HTMLElement>) {
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
    dragRef.current = null;
  }

  return (
    <>
      <div className="ui-avatar-stage" data-ui-surface="gray">
        {actions ? <div className="ui-avatar-preview-actions">{actions}</div> : null}
        <div className={classNames("ui-avatar-frame", source && "is-cropper", photoDraggable && "is-photo-draggable")} ref={frameRef}>
          {source ? (
            <>
              <img alt="" className={`ui-avatar-media is-filter-${filterId}`} data-ui-avatar-media-id={cropperId} draggable={false} src={source} />
              <div
                aria-label={cropLabel}
                className={classNames("ui-avatar-crop-box", photoDraggable && "is-photo-draggable")}
                data-ui-avatar-crop-id={cropperId}
                onPointerCancel={stopDrag}
                onPointerDown={(event) => startDrag("move", event)}
                onPointerMove={moveDrag}
                onPointerUp={stopDrag}
                role="img"
              >
                {cropHandles.map((handle) => (
                  <span
                    aria-hidden="true"
                    className="ui-avatar-crop-handle"
                    data-handle={handle}
                    key={handle}
                    onPointerDown={(event) => {
                      event.stopPropagation();
                      startDrag(handle, event);
                    }}
                  />
                ))}
              </div>
            </>
          ) : (
            <span aria-label={fallbackLabel} className="ui-avatar-default" role="img">
              <span aria-hidden="true" className="ui-avatar-initials">{fallbackInitials}</span>
            </span>
          )}
        </div>
        {previewFooter ? <div className="ui-avatar-preview-footer">{previewFooter}</div> : null}
      </div>
      {source && filterControls ? <div className="ui-avatar-filter-shell" data-ui-surface="white">{filterControls}</div> : null}
    </>
  );
}

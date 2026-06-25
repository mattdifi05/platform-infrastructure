"use client";

import { useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import { classNames } from "./classNames";
import { cssEscape } from "./cssom";
import { useDynamicCssProperties } from "./styleMotion";

type VirtualListItemRender<TItem> = (item: TItem, index: number) => ReactNode;

type VirtualListProps<TItem> = {
  activeIndex?: number;
  className?: string;
  itemHeight: number;
  items: TItem[];
  overscan?: number;
  renderItem: VirtualListItemRender<TItem>;
  viewportHeight: number;
};

const virtualListDynamicProperties = [
  "--ui-virtual-list-after",
  "--ui-virtual-list-before",
  "--ui-virtual-list-height",
  "--ui-virtual-list-item-height",
] as const;

export function VirtualList<TItem>({
  activeIndex,
  className,
  itemHeight,
  items,
  overscan = 4,
  renderItem,
  viewportHeight,
}: VirtualListProps<TItem>) {
  const listId = useId().replace(/:/g, "");
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const totalHeight = items.length * itemHeight;
  const visibleWindow = useMemo(() => {
    const first = Math.max(0, Math.floor(scrollTop / itemHeight) - overscan);
    const visibleCount = Math.ceil(viewportHeight / itemHeight) + overscan * 2;
    const last = Math.min(items.length, first + visibleCount);
    return { first, last };
  }, [itemHeight, items.length, overscan, scrollTop, viewportHeight]);
  const spacerBefore = visibleWindow.first * itemHeight;
  const spacerAfter = Math.max(0, totalHeight - visibleWindow.last * itemHeight);
  useDynamicCssProperties(
    `.ui-virtual-list[data-ui-virtual-list-id="${cssEscape(listId)}"]`,
    {
      "--ui-virtual-list-after": `${spacerAfter}px`,
      "--ui-virtual-list-before": `${spacerBefore}px`,
      "--ui-virtual-list-height": `${viewportHeight}px`,
      "--ui-virtual-list-item-height": `${itemHeight}px`,
    },
    virtualListDynamicProperties,
  );

  useEffect(() => {
    if (activeIndex === undefined) return;
    const scrollNode = scrollRef.current;
    if (!scrollNode) return;
    const itemTop = activeIndex * itemHeight;
    const itemBottom = itemTop + itemHeight;
    if (itemTop < scrollNode.scrollTop) scrollNode.scrollTop = itemTop;
    if (itemBottom > scrollNode.scrollTop + viewportHeight) scrollNode.scrollTop = itemBottom - viewportHeight;
  }, [activeIndex, itemHeight, viewportHeight]);

  return (
    <div
      className={classNames("ui-virtual-list", className)}
      data-ui-virtual-list-id={listId}
      data-virtual-list=""
      onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
      ref={scrollRef}
    >
      <div aria-hidden="true" className="ui-virtual-list-spacer-before" />
      {items.slice(visibleWindow.first, visibleWindow.last).map((item, offset) => {
        const index = visibleWindow.first + offset;
        return (
          <div className="ui-virtual-list-item" data-virtual-index={index} key={index}>
            {renderItem(item, index)}
          </div>
        );
      })}
      <div aria-hidden="true" className="ui-virtual-list-spacer-after" />
    </div>
  );
}

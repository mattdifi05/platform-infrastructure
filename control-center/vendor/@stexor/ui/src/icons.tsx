"use client";

import { config, type IconDefinition } from "@fortawesome/fontawesome-svg-core";
import {
  faArrowRight,
  faArrowRightToBracket,
  faArrowsRotate,
  faBars,
  faBell,
  faBolt,
  faBookOpen,
  faBookmark,
  faCalendarDays,
  faCamera,
  faChartLine,
  faCheck,
  faChevronDown,
  faChevronLeft,
  faChevronRight,
  faCircleCheck,
  faCircleInfo,
  faClockRotateLeft,
  faCode,
  faCoins,
  faComments,
  faCopy,
  faDatabase,
  faDiagramProject,
  faDownload,
  faEllipsis,
  faEnvelope,
  faFileArrowUp,
  faFileImage,
  faFloppyDisk,
  faFolderOpen,
  faGear,
  faGlobe,
  faLanguage,
  faLeaf,
  faLightbulb,
  faListCheck,
  faMagnifyingGlass,
  faMap,
  faMobileScreen,
  faMoon,
  faPaste,
  faPen,
  faPenNib,
  faPlay,
  faRotateLeft,
  faRotateRight,
  faScissors,
  faShieldHalved,
  faSliders,
  faSun,
  faTableCellsLarge,
  faTableColumns,
  faTrash,
  faTriangleExclamation,
  faUpload,
  faUser,
  faWandMagicSparkles,
  faXmark,
} from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import type { ComponentPropsWithoutRef, ComponentType } from "react";

config.autoAddCss = false;

type IconProps = Omit<ComponentPropsWithoutRef<typeof FontAwesomeIcon>, "height" | "icon" | "size" | "style" | "width"> & {
  size?: number | string;
};

export type IconType = ComponentType<IconProps>;

function makeIcon(icon: IconDefinition, displayName: string): IconType {
  function Icon({ className, size = "1em", ...props }: IconProps) {
    const dimension = typeof size === "number" ? `${size}px` : size;
    const iconClassName = className ? `svg-icon ${className}` : "svg-icon";

    return (
      <FontAwesomeIcon
        aria-hidden="true"
        className={iconClassName}
        focusable="false"
        height={dimension}
        icon={icon}
        width={dimension}
        {...props}
      />
    );
  }
  Icon.displayName = displayName;
  return Icon;
}

export const AlertTriangle = makeIcon(faTriangleExclamation, "AlertTriangle");
export const ArrowRight = makeIcon(faArrowRight, "ArrowRight");
export const BadgeCheck = makeIcon(faCircleCheck, "BadgeCheck");
export const Bell = makeIcon(faBell, "Bell");
export const Braces = makeIcon(faCode, "Braces");
export const Calendar = makeIcon(faCalendarDays, "Calendar");
export const Camera = makeIcon(faCamera, "Camera");
export const Check = makeIcon(faCheck, "Check");
export const ChevronDown = makeIcon(faChevronDown, "ChevronDown");
export const ChevronLeft = makeIcon(faChevronLeft, "ChevronLeft");
export const ChevronRight = makeIcon(faChevronRight, "ChevronRight");
export const CircleInfo = makeIcon(faCircleInfo, "CircleInfo");
export const Copy = makeIcon(faCopy, "Copy");
export const Database = makeIcon(faDatabase, "Database");
export const DoorOpen = makeIcon(faDownload, "DoorOpen");
export const FileArrowUp = makeIcon(faFileArrowUp, "FileArrowUp");
export const FileImage = makeIcon(faFileImage, "FileImage");
export const Globe2 = makeIcon(faGlobe, "Globe2");
export const History = makeIcon(faClockRotateLeft, "History");
export const Languages = makeIcon(faLanguage, "Languages");
export const LayoutDashboard = makeIcon(faTableColumns, "LayoutDashboard");
export const LayoutGrid = makeIcon(faTableCellsLarge, "LayoutGrid");
export const LogIn = makeIcon(faArrowRightToBracket, "LogIn");
export const Mail = makeIcon(faEnvelope, "Mail");
export const MoreHorizontal = makeIcon(faEllipsis, "MoreHorizontal");
export const Moon = makeIcon(faMoon, "Moon");
export const Paste = makeIcon(faPaste, "Paste");
export const Pencil = makeIcon(faPen, "Pencil");
export const Play = makeIcon(faPlay, "Play");
export const RefreshCcw = makeIcon(faArrowsRotate, "RefreshCcw");
export const RotateLeft = makeIcon(faRotateLeft, "RotateLeft");
export const RotateRight = makeIcon(faRotateRight, "RotateRight");
export const Rows3 = makeIcon(faBars, "Rows3");
export const Save = makeIcon(faFloppyDisk, "Save");
export const Scissors = makeIcon(faScissors, "Scissors");
export const Search = makeIcon(faMagnifyingGlass, "Search");
export const ShieldCheck = makeIcon(faShieldHalved, "ShieldCheck");
export const Sliders = makeIcon(faSliders, "Sliders");
export const Smartphone = makeIcon(faMobileScreen, "Smartphone");
export const Sun = makeIcon(faSun, "Sun");
export const Trash = makeIcon(faTrash, "Trash");
export const Upload = makeIcon(faUpload, "Upload");
export const UserRound = makeIcon(faUser, "UserRound");
export const X = makeIcon(faXmark, "X");

const extendedIconRegistry = {
  bolt: makeIcon(faBolt, "FontAwesomeBolt"),
  bookOpen: makeIcon(faBookOpen, "FontAwesomeBookOpen"),
  bookmark: makeIcon(faBookmark, "FontAwesomeBookmark"),
  calendarDays: Calendar,
  chartLine: makeIcon(faChartLine, "FontAwesomeChartLine"),
  coins: makeIcon(faCoins, "FontAwesomeCoins"),
  comments: makeIcon(faComments, "FontAwesomeComments"),
  diagramProject: makeIcon(faDiagramProject, "FontAwesomeDiagramProject"),
  download: makeIcon(faDownload, "FontAwesomeDownload"),
  folderOpen: makeIcon(faFolderOpen, "FontAwesomeFolderOpen"),
  gear: makeIcon(faGear, "FontAwesomeGear"),
  leaf: makeIcon(faLeaf, "FontAwesomeLeaf"),
  lightbulb: makeIcon(faLightbulb, "FontAwesomeLightbulb"),
  listCheck: makeIcon(faListCheck, "FontAwesomeListCheck"),
  map: makeIcon(faMap, "FontAwesomeMap"),
  penNib: makeIcon(faPenNib, "FontAwesomePenNib"),
  shieldHalved: ShieldCheck,
  tableColumns: LayoutDashboard,
  wandMagicSparkles: makeIcon(faWandMagicSparkles, "FontAwesomeWandMagicSparkles"),
} satisfies Record<string, IconType>;

export const uiIconRegistry: Record<string, IconType> = {
  alertTriangle: AlertTriangle,
  arrowRight: ArrowRight,
  badgeCheck: BadgeCheck,
  bell: Bell,
  braces: Braces,
  calendar: Calendar,
  camera: Camera,
  check: Check,
  chevronDown: ChevronDown,
  chevronLeft: ChevronLeft,
  chevronRight: ChevronRight,
  circleInfo: CircleInfo,
  copy: Copy,
  database: Database,
  doorOpen: DoorOpen,
  fileArrowUp: FileArrowUp,
  fileImage: FileImage,
  globe: Globe2,
  history: History,
  languages: Languages,
  layoutDashboard: LayoutDashboard,
  layoutGrid: LayoutGrid,
  logIn: LogIn,
  mail: Mail,
  moreHorizontal: MoreHorizontal,
  moon: Moon,
  paste: Paste,
  pencil: Pencil,
  play: Play,
  refreshCcw: RefreshCcw,
  rotateLeft: RotateLeft,
  rotateRight: RotateRight,
  rows3: Rows3,
  save: Save,
  scissors: Scissors,
  search: Search,
  shieldCheck: ShieldCheck,
  sliders: Sliders,
  smartphone: Smartphone,
  sun: Sun,
  trash: Trash,
  upload: Upload,
  userRound: UserRound,
  x: X,
  ...extendedIconRegistry,
};

export type UiIconName = keyof typeof uiIconRegistry;

export function resolveIcon(icon?: IconType | UiIconName | null, fallback: UiIconName = "circleInfo"): IconType {
  const fallbackIcon = uiIconRegistry[fallback] ?? CircleInfo;
  if (!icon) return fallbackIcon;
  return typeof icon === "string" ? uiIconRegistry[icon] ?? fallbackIcon : icon;
}

export function getUiIcon(iconName: UiIconName): IconType {
  return resolveIcon(iconName);
}

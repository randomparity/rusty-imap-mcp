local repository = "https://github.com/randomparity/rusty-imap-mcp"

local function is_external(target)
  return target:match("^[%a][%w+.-]*:") or target:match("^//")
end

local function split_fragment(target)
  local path, fragment = target:match("^([^#]*)(#.*)$")
  if path then
    return path, fragment
  end
  return target, ""
end

function Link(link)
  local target = link.target
  if target:match("^#") or is_external(target) then
    return link
  end

  local path, fragment = split_fragment(target)
  local route = path:match("/$") and "tree" or "blob"
  link.target = repository .. "/" .. route .. "/main/" .. path .. fragment
  return link
end
